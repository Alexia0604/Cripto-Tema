#pragma once
#include <stdio.h>

int calculate_sym_elements_id(int id1, int id2)
{
    return (id1 < id2) ? (id1 * 100 + id2) : (id2 * 100 + id1);
}