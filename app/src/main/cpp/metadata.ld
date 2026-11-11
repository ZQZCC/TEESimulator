SECTIONS {
    /DISCARD/ : {
        *(.comment)
        *(.note.android.ident)
    }
}
INSERT BEFORE .text;
