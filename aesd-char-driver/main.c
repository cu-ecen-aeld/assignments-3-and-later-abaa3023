/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h> //size_t    
#include <linux/cdev.h>
#include <linux/kernel.h> //containerof
#include <linux/slab.h> //kmalloc
#include <linux/uaccess.h>	/* copy_*_user */
#include <linux/fs.h> // file_operations

#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

#define DELIMITER           ('\n')

MODULE_AUTHOR("abaa3023"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int allocate_memory(struct working_buffer *ptr, int size)
{
    int retval = 0;
    char *temp_ptr;
    if(ptr->size == 0)
    {
        ptr->buffer = kmalloc(size,GFP_KERNEL);
        if(!ptr->buffer)
        {
            retval = -ENOMEM;  
        }
    }
    else
    {
        temp_ptr = krealloc(ptr->buffer,ptr->size + size,GFP_KERNEL);
        if(!temp_ptr)
        {
            kfree(ptr->buffer);
            retval = -ENOMEM; 
        }
        else
        {
            ptr->buffer = temp_ptr;
        }
    }
    return retval;
}


#ifdef __KERNEL__
loff_t ret_offset(struct aesd_circular_buffer *buffer,unsigned int buf_no, unsigned int offset_within_buf)
{
    int i,offset = 0;
    printk("aesdchar: Searching for return offset");
    if(buf_no>(AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)-1)
    {
        printk("aesdchar: Invalid buffer number");
        return -1;
    }
    if(offset_within_buf > (buffer->entry[buf_no].size - 1))
    {
        printk("aesdchar: Invalid offset");
        return -1;
    }
    for(i=0;i<(buf_no);i++)
    {
        printk("aesdchar: i %d ",i);
        if(buffer->entry[i].size == 0)
        {
            return -1;
        }
        offset += buffer->entry[i].size;
    }
    return (offset + offset_within_buf);
}
#endif


static long aesd_adjust_file_offset(struct file *filp,unsigned int write_cmd, unsigned int write_cmd_offset)
{
    struct aesd_dev *data;
    loff_t offset;
    int ret_val;
    if(!filp->private_data)
    {
        return -EINVAL;
    }
    data = filp->private_data;
    if (mutex_lock_interruptible(&data->lock))
    {
        return -ERESTARTSYS;
    }
    offset = ret_offset(&data->circular_buffer,write_cmd,write_cmd_offset);
    
    if(offset == -1)
    {
        ret_val = -EINVAL;
    }
    else
    {
        filp->f_pos = offset;
        ret_val = 0;
    }
    mutex_unlock(&data->lock);
    return ret_val;
}
static int find_delimiter(char *ptr, int size)
{
    int i;
    for(i = 0;i<size;i++)
    {
        if(ptr[i] == DELIMITER)
        {
            return i;
        }
    }
    return -1;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *info_dev;
    info_dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = info_dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    filp->private_data = NULL;
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *data;
    size_t relative_byte_offset;
    struct aesd_buffer_entry *ret_buf;
    int bytes_to_eob;
    int bytes_to_copy;
    if(!filp || !filp->private_data)
    {
        retval = -EINVAL;
        return retval;
    }
    data = filp->private_data;
    if (mutex_lock_interruptible(&data->lock))
    {
        retval = -EINTR;
        return retval;
    }
    ret_buf = aesd_circular_buffer_find_entry_offset_for_fpos(&data->circular_buffer,
                                                            *f_pos, 
                                                            &relative_byte_offset);
    if(!ret_buf)
    {
        *f_pos = 0;
        mutex_unlock(&data->lock);
        return retval;
    }
    bytes_to_eob = (ret_buf->size - relative_byte_offset);
    bytes_to_copy = bytes_to_eob<count?bytes_to_eob:count;
    *f_pos += bytes_to_copy;
    if (copy_to_user(buf, (ret_buf->buffptr + relative_byte_offset), bytes_to_copy)) 
    {
	retval = -EFAULT;
	mutex_unlock(&data->lock);
        return retval;
    }
    retval += bytes_to_copy;
    mutex_unlock(&data->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *data;
    struct aesd_buffer_entry enqueue_buffer;
    struct working_buffer copy_buffer;
    int mem_to_malloc,start_ptr = 0,delim_loc = 0;
    char *free_buffer;
    if(!filp || !filp->private_data)
    {
        retval = -EINVAL;
        return retval;
    }
    data = filp->private_data;
    if(count == 0)
    {
        return retval;
    }
    
    copy_buffer.buffer = kmalloc(count,GFP_KERNEL);
    if(!copy_buffer.buffer)
    {
        retval = -ENOMEM;
        kfree(copy_buffer.buffer);
        return retval;
    }
    copy_buffer.size = count;
    if (copy_from_user(copy_buffer.buffer, buf, count)) 
    {
	retval = -EFAULT;
        kfree(copy_buffer.buffer);
        return retval;
    }

    if (mutex_lock_interruptible(&data->lock))
    {
        retval = -EINTR;
        kfree(copy_buffer.buffer);
        return retval;
    }
    while(delim_loc != -1)
    {
        delim_loc = find_delimiter(&copy_buffer.buffer[start_ptr],(count - start_ptr));
        mem_to_malloc = delim_loc==-1?(count - start_ptr):((delim_loc-start_ptr) +1);
        if(allocate_memory(&data->working_buffer, mem_to_malloc)<0)
        {
            retval = -ENOMEM;
	    mutex_unlock(&data->lock);
            kfree(copy_buffer.buffer);
            return retval;
        }
        memcpy((data->working_buffer.buffer + data->working_buffer.size),(copy_buffer.buffer+start_ptr),mem_to_malloc);
        data->working_buffer.size += mem_to_malloc;
        if(delim_loc != -1)
        {
            enqueue_buffer.buffptr = data->working_buffer.buffer;  
            enqueue_buffer.size = data->working_buffer.size;
            free_buffer = aesd_circular_buffer_add_entry(&data->circular_buffer,&enqueue_buffer);
            if(free_buffer)
            {
                kfree(free_buffer);
            }
            data->working_buffer.size = 0;
            start_ptr += delim_loc+1;
        }
        retval += mem_to_malloc;
    }
    mutex_unlock(&data->lock);
    kfree(copy_buffer.buffer);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t ret_val;
    struct aesd_dev *data;
    if(!filp->private_data)
    {
        ret_val = -EINVAL;
        return ret_val;
    }
    data = filp->private_data;
    if (mutex_lock_interruptible(&data->lock))
    {
        ret_val = -EINTR;      
        return ret_val;
    }
    ret_val = fixed_size_llseek(filp,off,whence, data->circular_buffer.size);
    mutex_unlock(&data->lock);
    return ret_val;
}


long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int retval = 0;
    struct aesd_seekto seekto;
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

    switch(cmd)
    {
        case AESDCHAR_IOCSEEKTO:
            if(copy_from_user(&seekto,(const void __user *)arg,sizeof(seekto))!=0)
            {
                retval = -EFAULT;
            } 
            else
            {
                retval = aesd_adjust_file_offset(filp,seekto.write_cmd, seekto.write_cmd_offset);
            }
            break;
        default:
            retval = -ENOTTY;
            break;
    }
    return retval;
}

struct file_operations aesd_fops = {
    .owner =            THIS_MODULE,
    .llseek =           aesd_llseek,
    .read =             aesd_read,
    .write =            aesd_write,
    .unlocked_ioctl =   aesd_ioctl,
    .open =             aesd_open,
    .release =          aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    /**
     * TODO: initialize the AESD specific portion of the device
     */

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}


void destroy_circular_buffer(struct aesd_circular_buffer *buffer)
{
    uint8_t ptr;
    char *entry;
    if(!buffer)
    {
        return;
    }
    if(buffer->in_offs == buffer->out_offs && !buffer->full)
    {
        return;
    }
    ptr =  buffer->out_offs;
    entry = (char *)buffer->entry[ptr].buffptr;
    while(entry)
    {
        #ifdef __KERNEL__
        kfree(entry);
        #else
        free(entry);
        #endif
        ptr = ((ptr + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
        if(ptr == buffer->in_offs)
        {
            break;
        }
        entry = (char *)buffer->entry[ptr].buffptr;
    }

}


void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    if(mutex_lock_interruptible(&aesd_device.lock))
    {
        PDEBUG("MUTEX UNLOCK FAILED");
    }
    destroy_circular_buffer(&aesd_device.circular_buffer);
    mutex_unlock(&aesd_device.lock);
    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);

