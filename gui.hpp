#pragma once
#include "ansi.h"
#include <iostream>

class GUI
{
public:
    const std::string cyan_plus   = Colors[White] + "[" + Colors[Cyan]   + "+" + Colors[White] + "]";
    const std::string purple_plus = Colors[White] + "[" + Colors[Purple] + "+" + Colors[White] + "]";

    void configure_console()
    {
        // Linux terminals support ANSI escape codes natively — no setup needed.
    }
};