/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#include <linux/module.h>
#include <linux/printk.h>
#else
#include <string.h>
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
    //Error handling for invalid inputs
    if(buffer == NULL){
        return NULL;
    }
    if(entry_offset_byte_rtn == NULL){
        return NULL;
    }
    uint8_t nElements = 0;              //Stores number of elements in the buffer
    if(buffer->in_offs > buffer->out_offs){
        nElements = (buffer->in_offs - buffer->out_offs) + 1;
    }
    else if(buffer->out_offs > buffer->in_offs){
        nElements = (AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs) + buffer->in_offs + 1;
        // nElements = (buffer->out_offs - buffer->in_offs) + 1;
    }
    else{                               //in and out pointers are equal
        if(buffer->full){
            nElements = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        }
        else{
            nElements = 0;
        }
    }

    //traversing thorugh the buffer to check the offset
    int pread = buffer->out_offs;           //Start reading from out pointer
    int count = 0;
    while(count < nElements){
        if(char_offset < buffer->entry[pread].size){
            //offset located in the current buffer
            *entry_offset_byte_rtn = char_offset;
            return (&buffer->entry[pread]);
        }
        //Offset beyond the current buffer entry
        char_offset -= buffer->entry[pread].size;
        //handling incrementation and wrap around
        pread++;
        if(pread == AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED){
            pread = 0;
        }
        count++;
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
const char *aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description 
    */
   const char* pret = NULL;
   //Handling error cases below
   //Check if any of the input parameter pointer is NULL
   if(buffer == NULL){
       return pret;
   }
   if(add_entry == NULL){
       return pret;
   }
   //Check if any of the element of the pointer to the buffer structure is NULL or 0
   if(add_entry->buffptr == NULL){
       return pret;
   }
   if(add_entry->size == 0){
       return pret;
   }
   if(buffer->full){
       pret = buffer->entry[buffer->in_offs].buffptr;
       //Increment the out offset pointer when buffer is full
       buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
   }
   //Writing to the buffer on the input pointer
   buffer->entry[buffer->in_offs] = *add_entry;
//    printk(KERN_INFO "in[%d] out[%d] [%p]\n", buffer->in_offs, buffer->out_offs, add_entry);
   //Increment buffer each time
   buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
   //managing the wrap around conditions
   if((buffer->in_offs == buffer->out_offs) && (!buffer->full)){
        buffer->full = true;
   }
   return pret;
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}