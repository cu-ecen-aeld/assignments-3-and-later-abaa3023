/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 * seeked help from Guru and fellow classmates regarding allocating buffer function
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
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("abaa3023"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

static int allocate_memory(struct aesd_dev *dev, int size)
{
    int retval = 0;
    if(dev->size == 0)
    {
        dev->buffer = kmalloc(size, GFP_KERNEL);
        if(!dev->buffer)
        {
            retval = -ENOMEM;  
        }
    }
    else
    {
        char *tmp = krealloc(dev->buffer,dev->size + size,GFP_KERNEL);
        if(!tmp)
        {
            kfree(dev->buffer);
            retval = -ENOMEM;
        }
        else
        {
            dev->buffer = tmp;
        }
    }
    return retval;
}

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev = NULL;;
    PDEBUG("open");
    
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * Remove assignment of private data.
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0, offset, user_copy_bytes;
    struct aesd_dev *dev;
    struct aesd_buffer_entry *entry;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    if(!filp || !filp->private_data)
    {
        retval = -EINVAL;
        return retval;
    }
    dev = filp->private_data;
    if (mutex_lock_interruptible(&dev->m))
    {
        retval = -EINTR;
        return retval;
    }
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &offset);
    if(!entry)
    {
        *f_pos = 0;
        mutex_unlock(&dev->m);
        return retval;
    }
    
    if((entry->size - offset)<count)
    	user_copy_bytes = (entry->size - offset);
    else
    	user_copy_bytes = count;
    
    *f_pos += user_copy_bytes;
    if (copy_to_user(buf, (entry->buffptr + offset), user_copy_bytes)) 
    {
		retval = -EFAULT;
		mutex_unlock(&dev->m);
		return retval;
    }
    
    retval += user_copy_bytes;
    mutex_unlock(&dev->m);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *data;
    struct aesd_buffer_entry enqueue_buffer;
    int mem_to_malloc,i,start_ptr = 0;
    char *free_buffer, *buffer;
    size_t size;
    if(!filp || !filp->private_data)
    {
        retval = -EINVAL;
        return retval;
    }
    data = filp->private_data;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    if(count == 0)
    {
        return retval;
    }

    //block on mutex lock, can be interrupted by signal
    if (mutex_lock_interruptible(&data->m))
    {
        retval = -EINTR;
        return retval;
    }
    
    buffer = kmalloc(count,GFP_KERNEL);
    if(!buffer)
    {
        retval = -ENOMEM;
        mutex_unlock(&data->m);
	return retval;
    }
    size = count;
    
    if (copy_from_user(buffer, buf, count)) 
    {
	retval = -EFAULT;
        mutex_unlock(&data->m);
	return retval;
    }

    for(i = 0;i<count;i++)
    {
        if(buffer[start_ptr+i]=='\n')
        {
            //check if working buffer size is 0, if it is malloc
            //else realloc 
            mem_to_malloc = (i-start_ptr) +1;

            if(allocate_memory(&data, mem_to_malloc)<0)
            {
                retval = -ENOMEM;
		 kfree(buffer);
		 mutex_unlock(&data->m);
		 return retval;
            }
            //Copy data to global buffer
            memcpy((data->buffer + data->size),(buffer+start_ptr),mem_to_malloc);
            data->size += mem_to_malloc;
            enqueue_buffer.buffptr = data->buffer;  
            enqueue_buffer.size = data->size;
            //enqueue data
            free_buffer = aesd_circular_buffer_add_entry(&data->circular_buffer,&enqueue_buffer);
            //if overwrite was performed, free overwrtten buffer
            if(free_buffer)
            {
                kfree(free_buffer);
            }
            data->size = 0;
            //update start pointer in case multiple \n present
            start_ptr = i+1;
            retval += mem_to_malloc;
        }
        if(i == count - 1)
        {
            if(buffer[i] != '\n')
            {
                mem_to_malloc = (i-start_ptr) +1;
                //check if working buffer size is 0, if it is malloc
                //else realloc 
                if(allocate_memory(&data, mem_to_malloc)<0)
                {
                    retval = -ENOMEM;
		     kfree(buffer);
		     mutex_unlock(&data->m);
		     return retval;
                }
                memcpy((data->buffer + data->size),(buffer+start_ptr),mem_to_malloc);
                data->size += mem_to_malloc;
                retval += mem_to_malloc;
            }
        }
    }
    //free local buffer
    copy_buff_free: kfree(buffer);
    release_lock: mutex_unlock(&data->m);
    ret_func: return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.m);
    /**
     * TODO: initialize the AESD specific portion of the device
     */

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    mutex_destroy(&aesd_device.m);
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
