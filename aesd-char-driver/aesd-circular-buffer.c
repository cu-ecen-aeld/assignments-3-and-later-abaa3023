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
#include <linux/slab.h>
#else
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include "aesd-circular-buffer.h"


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
    int total_size = 0;
    int num_bufs_iterated;
    int buf_idx ;
    if(!buffer || !entry_offset_byte_rtn)
    {
        return NULL;
    }

    for(num_bufs_iterated =0,buf_idx =buffer->out_offs;
            num_bufs_iterated<AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
            buf_idx = ((buf_idx + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED),num_bufs_iterated++)
            {
                struct aesd_buffer_entry *entry = &(buffer->entry[buf_idx]);
                if(entry->size == 0)
                {
                    return NULL;
                }
                if((total_size + entry->size -1) >= char_offset)
                {
                    
                    *entry_offset_byte_rtn = (char_offset - total_size);
                    return entry;
                }
                total_size += entry->size;
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
    char *ret_val = NULL;
    if(!buffer || !add_entry)
    {
        return ret_val;
    }
    if(buffer->in_offs == buffer->out_offs && buffer->full)
    {
        ret_val = (char*)buffer->entry[buffer->out_offs].buffptr;
        buffer->size -= buffer->entry[buffer->out_offs].size;
        buffer->out_offs = ((buffer->out_offs + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
    }
    buffer->entry[buffer->in_offs].buffptr = add_entry->buffptr;
    buffer->entry[buffer->in_offs].size = add_entry->size;
    buffer->size += add_entry->size;
    buffer->in_offs = ((buffer->in_offs + 1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED);
    if(buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
    else
    {
        buffer->full = false;
    }
    return ret_val;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
