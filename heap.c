#include "heap.h"
#include "tested_declarations.h"
#include "rdebug.h"
#include "tested_declarations.h"
#include "rdebug.h"

#define ChunkSize sizeof(struct memory_chunk_t)
#define FenceSize 4
#define PageSize 4096

int heap_setup(void){
    void *memory = custom_sbrk(0);
    if(memory == (void *) -1){
        return -1;
    }
    memory_manager.memory_start = memory;
    memory_manager.memory_size = PageSize;
    memory_manager.first_memory_chunk = NULL;
    return 0;
}

void heap_clean(void){
    custom_sbrk((intptr_t) memory_manager.memory_size * (-1));
    memory_manager.memory_size = 0;
    memory_manager.first_memory_chunk = NULL;
    memory_manager.memory_start = NULL;
}

void calculate_check_sum(struct memory_chunk_t *chunk){
    int sum = 0;

    for(size_t i = 0; i < ChunkSize- sizeof(int); i++) {
        sum += *((char*)chunk+i);
    }

    chunk->check_sum = sum;
}

void* heap_malloc(size_t size){
    if(size <= 0 || memory_manager.memory_start == NULL){
        return NULL;
    }

    struct memory_chunk_t *current_chunk = memory_manager.first_memory_chunk;

    // Searching for a free memory block
    while (current_chunk != NULL){
        if(current_chunk->free == 1 && current_chunk->size >= size){
            current_chunk->size = size;
            current_chunk->free = 0;

            for(int i = 0; i < FenceSize; i++) {
                *((uint8_t *)current_chunk + ChunkSize + i) = '#';
                *((uint8_t*)current_chunk + ChunkSize + i + current_chunk->size + FenceSize) = '#';
            }

            calculate_check_sum(current_chunk);

            return (void *)((uint8_t *)current_chunk + ChunkSize + FenceSize);
        }
        current_chunk = current_chunk->next;
    }


    // First block of memory
    if(memory_manager.first_memory_chunk == NULL){

        memory_manager.memory_size = size + 2*FenceSize + ChunkSize;

        memory_manager.memory_start = custom_sbrk(size + 2*FenceSize + ChunkSize);
        if (memory_manager.memory_start == (void *) -1) {
            memory_manager.memory_start = NULL;
            return NULL;
        }


        struct memory_chunk_t *new_chunk = ((struct memory_chunk_t*) memory_manager.memory_start);

        new_chunk->size = size;
        new_chunk->free = 0;
        new_chunk->next = NULL;
        new_chunk->prev = NULL;

        for(int i = 0; i < FenceSize; i++) {
            *((uint8_t *)new_chunk + ChunkSize + i) = '#';
            *((uint8_t*)new_chunk + ChunkSize + i + new_chunk->size + FenceSize) = '#';
        }

        calculate_check_sum(new_chunk);

        memory_manager.first_memory_chunk = new_chunk;

        return (void *)((uint8_t *)new_chunk + ChunkSize + FenceSize);
    }

    // Adding new memory block at the end
    void *new_memory = custom_sbrk(size + 2*FenceSize + ChunkSize);
    if (new_memory == (void *) -1) {
        new_memory = NULL;
        return NULL;
    }

    struct memory_chunk_t *last_chunk = memory_manager.first_memory_chunk;
    while (last_chunk->next != NULL){
        last_chunk = last_chunk->next;
    }

    memory_manager.memory_size += size + 2*FenceSize + ChunkSize;

    struct memory_chunk_t *new_chunk = (struct memory_chunk_t *) new_memory;

    new_chunk->size = size;
    new_chunk->free = 0;
    new_chunk->next = NULL;
    new_chunk->prev = last_chunk;
    last_chunk->next = new_chunk;


    for(int i = 0; i < FenceSize; i++) {
        *((uint8_t *)new_chunk + ChunkSize + i) = '#';
        *((uint8_t*)new_chunk + ChunkSize + i + new_chunk->size + FenceSize) = '#';
    }

    calculate_check_sum(new_chunk);
    calculate_check_sum(last_chunk);

    return (void *)((uint8_t *)new_chunk + ChunkSize + FenceSize);
}


void* heap_calloc(size_t number, size_t size){
    if(number <= 0 || size <= 0){
        return NULL;
    }

    void *allocated_memory = heap_malloc(number * size);
    if(allocated_memory == NULL){
        return NULL;
    }

    memset(allocated_memory, 0, number * size);

    return allocated_memory;
}

void* heap_realloc(void* memblock, size_t count){
    if(memblock == NULL){
        return heap_malloc(count);
    }

    if(count <= 0){
        heap_free(memblock);
        return NULL;
    }

    if(get_pointer_type(memblock) != pointer_valid){
        return NULL;
    }

    struct memory_chunk_t *current_chunk = memory_manager.first_memory_chunk;
    int found = 0;

    while (current_chunk != NULL){
        if((void *)((uint8_t*)current_chunk + ChunkSize + FenceSize) == (uint8_t*)memblock){
            found = 1;
            break;
        }
        current_chunk = current_chunk->next;
    }

    if(found){

        if(current_chunk->next != NULL) {
            size_t size = (uint8_t*)current_chunk->next - (uint8_t*)current_chunk - ChunkSize - FenceSize*2;
            if(size > current_chunk->size) {
                current_chunk->size = size;
            }
        }


        if(current_chunk->size >= count){
            current_chunk->size = count;

            for(int i = 0; i < FenceSize; i++) {
                *((uint8_t*)current_chunk + ChunkSize + i + current_chunk->size + FenceSize) = '#';
            }

            calculate_check_sum(current_chunk);
            return memblock;
        }

        if(current_chunk->next == NULL) {
            void *new_memory = custom_sbrk(count - current_chunk->size);
            if (new_memory == (void *) -1) {
                new_memory = NULL;
                return NULL;
            }

            memory_manager.memory_size += count - current_chunk->size;
            current_chunk->size = count;
            for(int i = 0; i < FenceSize; i++) {
                *((uint8_t*)current_chunk + ChunkSize + i + current_chunk->size + FenceSize) = '#';
            }
            calculate_check_sum(current_chunk);
            return memblock;
        }

        // Connecting chunks
        struct memory_chunk_t* memory = memory_manager.first_memory_chunk;
        struct memory_chunk_t *tmp = memory;

        while(memory) {
            if(memory->free == 1) {
                tmp = memory;
            }
            memory = memory->next;
            if(tmp->free && memory && memory->free == 1) {
                tmp->size += memory->size + ChunkSize + FenceSize*2;
                tmp->next = memory->next;
                calculate_check_sum(tmp);
                if(memory->next) {
                    memory->next->prev = tmp;
                    calculate_check_sum(memory);
                }
            } else {
                tmp = tmp->next;
                calculate_check_sum(tmp);
            }
            if(memory->next == NULL) {
                break;
            }
            memory = tmp;
        }

        if(current_chunk->next && current_chunk->next->free && current_chunk->size+current_chunk->next->size + ChunkSize + FenceSize*2 >= count) {
            current_chunk->next = current_chunk->next->next;
            current_chunk->size = count;

            calculate_check_sum(current_chunk);

            if(current_chunk->next->next) {
                current_chunk->next->next->prev = current_chunk;
                calculate_check_sum(current_chunk->next->next);
            }

            for(int i = 0; i < FenceSize; i++) {
                *((uint8_t*)current_chunk + ChunkSize + i + current_chunk->size + FenceSize) = '#';
            }

            return memblock;
        }

        // Allocating new memory
        char *new = heap_malloc(count);
        if(new == NULL) {
            return NULL;
        }
        for(size_t i = 0; i < current_chunk->size; i++) {
            *((uint8_t*)new+i) = *((uint8_t*)current_chunk + FenceSize + ChunkSize+i);
        }
        heap_free(memblock);
        return new;
    }
    return NULL;
}

void heap_free(void* memblock){
    if(memblock == NULL || heap_validate()){
        return;
    }

    if(get_pointer_type(memblock) != pointer_valid){
        return;
    }

    struct memory_chunk_t *current_chunk = memory_manager.first_memory_chunk;
    int found = 0;

    while (current_chunk != NULL){
        if((void *)((uint8_t*)current_chunk + ChunkSize + FenceSize) == (uint8_t*)memblock){
            found = 1;
            break;
        }
        current_chunk = current_chunk->next;
    }

    if(found){
        if(current_chunk->prev == NULL && current_chunk->next == NULL){
            custom_sbrk(memory_manager.memory_size*(-1));
            memory_manager.memory_size = 0;
            memory_manager.first_memory_chunk = NULL;
            return;
        }

        current_chunk->free = 1;
        if(current_chunk->next != NULL) {
            size_t size = (uint8_t*)current_chunk->next - (uint8_t*)current_chunk - ChunkSize - FenceSize*2;
            if(size > current_chunk->size) {
                current_chunk->size = size;
            }
        }

        calculate_check_sum(current_chunk);

        // Connecting chunks after free
        current_chunk = memory_manager.first_memory_chunk;
        while (current_chunk != NULL){
            if(current_chunk->free == 1 && current_chunk->next && current_chunk->next->free == 1){

                current_chunk->next = current_chunk->next->next;

                if(current_chunk->next != NULL) {
                    size_t size = (uint8_t*)current_chunk->next - (uint8_t*)current_chunk - ChunkSize - FenceSize*2;
                    if(size > current_chunk->size) {
                        current_chunk->size = size;
                    }
                }

                calculate_check_sum(current_chunk);

            }
            if(current_chunk->prev == NULL && current_chunk->next == NULL){
                custom_sbrk(memory_manager.memory_size*(-1));
                memory_manager.memory_size = 0;
                memory_manager.first_memory_chunk = NULL;
                return;
            }
            if(current_chunk->free == 1 && current_chunk->next && current_chunk->next->free == 1){

                current_chunk->next = current_chunk->next->next;

                if(current_chunk->next != NULL) {
                    size_t size = (uint8_t*)current_chunk->next - (uint8_t*)current_chunk - ChunkSize - FenceSize*2;
                    if(size > current_chunk->size) {
                        current_chunk->size = size;
                    }
                }

                calculate_check_sum(current_chunk);
            }
            if(current_chunk->prev == NULL && current_chunk->next == NULL){
                custom_sbrk(memory_manager.memory_size*(-1));
                memory_manager.memory_size = 0;
                memory_manager.first_memory_chunk = NULL;
                return;
            }
            current_chunk = current_chunk->next;
        }
    }
}

size_t   heap_get_largest_used_block_size(void){
    if(memory_manager.memory_start == NULL || memory_manager.first_memory_chunk == NULL || memory_manager.memory_size == 0){
        return 0;
    }

    if(heap_validate()){
        return 0;
    }

    struct memory_chunk_t* current_chunk = memory_manager.first_memory_chunk;
    size_t largest_size = 0;

    while (current_chunk != NULL){
        if(current_chunk->free == 0 && current_chunk->size > largest_size){
            largest_size = current_chunk->size;
        }
        current_chunk = current_chunk->next;
    }
    return largest_size;
}

enum pointer_type_t get_pointer_type(const void* const pointer){
    if(pointer == NULL){
        return pointer_null;
    }

    if(heap_validate() != 0){
        return pointer_heap_corrupted;
    }

    if(pointer<memory_manager.memory_start){
        return pointer_unallocated;
    }

    struct memory_chunk_t *current_chunk = memory_manager.first_memory_chunk;

    while(current_chunk != NULL){
        if((uint8_t *)pointer == (uint8_t *)current_chunk + ChunkSize + FenceSize && current_chunk->free == 0) {
            return pointer_valid;
        }
        if((uint8_t *)current_chunk <= (uint8_t *)pointer && (uint8_t *)current_chunk + ChunkSize > (uint8_t *)pointer) {
            return pointer_control_block;
        }
        if((char*)pointer > (char*)current_chunk + ChunkSize + FenceSize && (uint8_t *)pointer < (uint8_t *)current_chunk + ChunkSize + FenceSize + current_chunk->size && current_chunk->free == 0) {
            return pointer_inside_data_block;
        }
        if((uint8_t *)pointer >= (uint8_t *)current_chunk + ChunkSize + FenceSize + current_chunk->size && (uint8_t *)pointer < (uint8_t *)current_chunk + ChunkSize + 2*FenceSize + current_chunk->size && current_chunk->free == 0) {
            return pointer_inside_fences;
        }
        if((uint8_t *)pointer >= (uint8_t *)current_chunk + ChunkSize && (uint8_t *)pointer < (uint8_t *)current_chunk + ChunkSize + FenceSize && current_chunk->free == 0) {
            return pointer_inside_fences;
        }
        current_chunk = current_chunk->next;
    }
    return pointer_unallocated;
}

int heap_validate(void){
    if(memory_manager.memory_start == NULL && memory_manager.first_memory_chunk == NULL){
        return 2;
    }

    struct memory_chunk_t *current_chunk = memory_manager.first_memory_chunk;

    while (current_chunk != NULL){

        int control_sum = 0;
        for(size_t i = 0; i < ChunkSize - sizeof(int); i++) {
            control_sum += *((char *)current_chunk+i);
        }
        if(control_sum != current_chunk->check_sum){
            return 3;
        }

        for(int i = 0; i < FenceSize; i++) {
            if(*((uint8_t*)current_chunk + ChunkSize + i) != '#' || *((uint8_t*)current_chunk+ ChunkSize + i + FenceSize + current_chunk->size) != '#') {
                return 1;
            }
        }

        current_chunk = current_chunk->next;
    }
    return 0;
}


