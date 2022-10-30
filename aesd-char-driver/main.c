/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 * seeked help from Guru and fellow classmates regarding allocating buffer function and aesd_ioctl function
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
    struct aesd_buffer_entry buffer_entry;
    int delimiter_idx = 0, update_size,i,first_idx = 0;
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

    if (mutex_lock_interruptible(&data->m))
    {
        retval = -EINTR;
        return retval;
    }
    
    buffer = kmalloc(count,GFP_KERNEL);
    if(!buffer)
    {
        retval = -ENOMEM;
        //mutex_unlock(&data->m);
	kfree(buffer);
	return retval;
    }
    size = count;
    
    if (copy_from_user(buffer, buf, count)) 
    {
	retval = -EFAULT;
        //mutex_unlock(&data->m);
	kfree(buffer);
	return retval;
    }

    while(delimiter_idx != -1)
    {
    	int *buffer_ptr = &buffer[first_idx];
	for(int i = 0;i<(count-first_idx);i++)
	{
		if(buffer_ptr[i] == '\n')
		{
		    delimiter_idx = i;
		    break;
		}
	else
		{
		    delimiter_idx = -1;
		}
	}
        
        if(delimiter_idx==-1)
        {
        	update_size = (count - first_idx);
        }
        else
        {
        	update_size = ((delimiter_idx-first_idx) +1);
        }
        
        if(allocate_memory(&data, update_size)<0)
        {
            retval = -ENOMEM;  
            kfree(buffer);
	    //mutex_unlock(&data->m);
	    return retval;
        }
        
        memcpy((data->buffer + data->size),(buffer+first_idx),update_size);
        data->size += update_size;
        
        if(delimiter_idx != -1)
        {
            buffer_entry.buffptr = data->buffer;  
            buffer_entry.size = data->size;
            free_buffer = aesd_circular_buffer_add_entry(&data->circular_buffer,&buffer_entry);
            if(free_buffer)
            {
                kfree(free_buffer);
            }
            data->size = 0;
            first_idx += delimiter_idx+1;
        }
        retval += update_size;
    }
    kfree(buffer);
    //mutex_unlock(&data->m);
    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int source)
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
    ret_val = fixed_size_llseek(filp, offset, source, data->circular_buffer.buff_size);
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
		struct aesd_dev *data;
		loff_t offset=0;
		int ret_val;
		if(!filp->private_data)
		{
			retval = -EINVAL;
		}
		data = filp->private_data;
		if (mutex_lock_interruptible(&data->lock))
		{
			retval = -ERESTARTSYS;
		}

		for(int i=0;i<(seekto.write_cmd);i++)
		{
			offset += data->circular_buffer->entry[i].size;
		}
		offset = offset + seekto.write_cmd_offset;
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
    .read =             aesd_read,
    .write =            aesd_write,
    .llseek =           aesd_llseek,
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
