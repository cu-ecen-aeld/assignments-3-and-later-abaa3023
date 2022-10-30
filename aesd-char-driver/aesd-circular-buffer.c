/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01, updated on 10/11/2022
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>

#else
#include <string.h>
#include <stdio.h>
#endif

#include "aesd-circular-buffer.h"

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

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    
    int nElements = 0, pos, idx;
    
    if(!buffer || !entry_offset_byte_rtn)
    {
        return NULL;
    }

    for(pos =0, idx =buffer->out_offs; pos < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; idx = ((idx + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED), pos++)
            {
                struct aesd_buffer_entry *entry = &(buffer->entry[idx]);
                if(entry->size == 0)
                {
                    return NULL;
                }
                
                if((nElements + entry->size -1) >= char_offset)
                {
                    
                    *entry_offset_byte_rtn = (char_offset - nElements);
                    return entry;
                }
                
                nElements += entry->size;
            } 
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
char* aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    
    if(!buffer || !add_entry)
    {
        return NULL;
    }
    
    char *ret = NULL;
    if(buffer->in_offs == buffer->out_offs && buffer->full)
    {
        ret = (char*)buffer->entry[buffer->out_offs].buffptr;
        buffer->size -= buffer->entry[buffer->out_offs].size;
        buffer->out_offs = ((buffer->out_offs + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
    }
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->size -= add_entry->size;
    buffer->in_offs = ((buffer->in_offs + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
    
    if(buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
    else
    {
        buffer->full = false;
    }
    return ret;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
