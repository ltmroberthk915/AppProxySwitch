# Shared MSVC warning configuration for first-party targets.
function(aps_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /W4
            /permissive-
            /Zc:__cplusplus
            /utf-8
            /w14242   # conversion from 'int' to 'uint16_t', possible loss of data
            /w14254   # operator conversion, possible loss of data
            /w14263   # member function does not override any base member
            /w14265   # class has virtual functions, but destructor is not virtual
            /w14287   # unsigned/negative constant mismatch
            /w14296   # expression is always false
            /w14311   # pointer truncation from void* to uint32_t
            /w14545   # expression before comma evaluates to a function
            /w14546   # call before comma, no side effects
            /w14547   # operator with no effect
            /w14549   # operator with no effect
            /w14555   # expression has no effect
            /w14640   # unsafe conversion between related types
            /w14826   # conversion is sign-extended
            /w14905   # wide string cast
            /w14906   # string cast
            /w14928   # illegal copy-initialization
        )
    endif()
endfunction()
