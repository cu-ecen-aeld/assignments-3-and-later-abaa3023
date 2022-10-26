/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("abaa3023"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;
    struct aesd_buffer_entry *pos = NULL;
    ssize_t read_bytes = 0;
    ssize_t buffer_entry_offset = 0;
    
    mutex_lock_interruptible(&aesd_device.m);
    pos = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->circular_buffer, *f_pos, &buffer_entry_offset);
    read_bytes = pos->size - buffer_entry_offset;
    
    if(read_bytes > count)
    {
    	read_bytes = count;
    }
    
    copy_to_user(buf, (pos->buffptr + buffer_entry_offset), read_bytes);
    retval = read_bytes
    *f_pos += retval;
    mutex_unlock(&aesd_device.m);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    struct aesd_dev *dev = (struct aesd_dev *)filp->private_data;
    mutex_lock_interruptible(&aesd_device.m);
    if(dev->buffer_entry.size == 0)
    {
    	dev->buffer_entry.buffptr = kmalloc((sizeof(char)*count),GFP_KERNEL);
    	memset(dev->buffer_entry.buffptr, 0, sizeof(char)*count);
    }
    else
    {
    	dev->buffer_entry.buffptr = krealloc(dev->buffer_entry.buffptr, (dev->buffer_entry.size + count)*sizeof(char), GFP_KERNEL);
    }
    
    copy_from_user((void *)(&dev->buffer_entry.buffptr[dev->buffer_entry.size]), buf, count);
    retval = count;
    dev->buffer_entry.size += count;
    for (int i=0; i<dev->buffer_entry.size; i++)
    {
    	if(dev->buffer_entry.buffptr[i] == '\n')
    	{
    		aesd_circular_buffer_add_entry(&dev->circular_buffer, &dev->buffer_entry);
    		dev->buffer_entry.buffptr = NULL;
    		dev->buffer_entry.size = 0;
    	}
    }
    mutex_unlock(&aesd_device.m);
    *f_pos = 0;
    return retval;
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
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device, 0, sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    
    mutex_init(&aesd_device.m);
    aesd_circular_buffer_init(&aesd_device.circular_buffer);
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
    
    struct aesd_buffer_entry *buffer_entry = NULL;
    int pos = 0;
    AESD_CIRCULAR_BUFFER_FOREACH(buffer_entry, &aesd_device.circular_buffer, pos){
    	if(buffer_entry->buffptr != NULL){
    		kfree(buffer_entry->buffptr);
    	}
    }
    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
