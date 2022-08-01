#ifndef OS_WINDOWS_SYMBOLENGINE_HPP
#define OS_WINDOWS_SYMBOLENGINE_HPP


namespace SymbolEngine {

    bool decode(const void* addr, char* buf, int buflen, int* offset, bool do_demangle);

    //bool demangle(const char* symbol, char* buf, int buflen);

    // given an address, attempts to retrieve the source file and line number.
    bool get_source_info(const void* addr, char* filename, size_t filename_len,
        int* line_no);


    // Scan the loaded modules. Add all directories for all loaded modules
    //  to the current search path, unless they are already part of the search
    //    path. Prior search path content is preserved, directories are only
    //   added, never removed.
    // If p_search_path_was_updated is not NULL, points to a bool which, upon
    //   successful return from the function, contains true if the search path
    //   was updated, false if no update was needed because no new DLLs were
    //   loaded or unloaded.
    // Returns true for success, false for error.
    // 
    
    //bool recalc_search_path(bool* p_search_path_was_updated = nullptr);

    // Print one liner describing state (if library loaded, which functions are
    // missing - if any, and the dbhelp API version)
    //void print_state_on(ostream* st);

    // Call at DLL_PROCESS_ATTACH.
    void pre_initialize();


};

#endif // OS_WINDOWS_SYMBOLENGINE_HPP