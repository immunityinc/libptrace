mmap
====

.. c:function:: struct pt_mmap *pt_mmap_new(void)

This function allocates a struct pt_mmap object and initializes it internally calling pt_mmap_init.

.. c:function:: void pt_mmap_init(struct pt_mmap *pm)

This function initializes a previously allocated 'pm' object.

.. c:function:: void pt_mmap_destroy(struct pt_mmap *pm)

This function removes every area objects stored in the tree 'pm'. Each leaf (area) is deallocated but the tree 'pm' itself isn't.
This function is specifically meant for static 'pm' objects.

.. c:function:: void pt_mmap_delete(struct pt_mmap *)

This function removes every area objects stored in the tree 'pm'. Each leaf (area) as well as the 'pm' tree itself is deallocated.
This function is specifically meant for dynamical 'pm' objects.

.. c:function:: struct pt_mmap_area *pt_mmap_area_new(void)

This function allocates a new struct pt_mmap_area object.

.. c:function:: void pt_mmap_area_init(struct pt_mmap_area *area)

This function initializes a previously allocated struct pt_mmap_area object.

.. c:function:: void pt_mmap_area_destroy(struct pt_mmap *pm, struct pt_mmap_area *area)

This function removes 'area' from 'pm'.

.. c:function:: void pt_mmap_area_delete(struct pt_mmap *pm, struct pt_mmap_area *area)

This function removes 'area' from 'pm' and deallocates 'area'.

.. c:function:: void pt_mmap_add_area(struct pt_mmap *pm, struct pt_mmap_area *area)

This function stores an 'area' object in the 'pm' tree.

.. c:function:: struct pt_mmap_area *pt_mmap_find_exact_area(struct pt_mmap *pm, unsigned long start, unsigned long end)

This function tries to find an area object stored in 'pm' matching the range [start,end]. If such an object can be found, the function
returns it, otherwise NULL is returned.

.. c:function:: struct pt_mmap_area *pt_mmap_find_area_from_address(struct pt_mmap *, unsigned long address)

This function tries to locate an area object  stored in 'pm' that would hold a particular 'address'. It returns it if it can find one, or 
returns NULL otherwise.

.. c:function:: struct pt_mmap_area *pt_mmap_find_area_from_range(struct pt_mmap *pm, unsigned long start, unsigned long end)

This function tries to locate an area object stored in 'pm' that would collide with the range [start,end]. It returns it if it can find one, or 
returns NULL otherwise.

.. c:function:: struct pt_mmap_area *pt_mmap_find_all_area_from_range_start(struct pt_mmap *, unsigned long, unsigned long)
.. c:function:: struct pt_mmap_area *pt_mmap_find_all_area_from_range_next(void)

These functions are the iterator corresponding to pt_mmap_find_area_from_range(). pt_mmap_find_all_area_from_range_start() is called to initialize the iterator and returns a first area. pt_mmap_find_all_area_from_range_next() may then be called subsequently to retrieve all the other areas. Due to the design of this API, it is not thread safe.

.. c:function:: int pt_mmap_load(struct pt_process *proc)

This functions is used to create the internal mmap tree stored in proc. This tree holds all the areas of the process.
