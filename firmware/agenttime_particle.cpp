// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#ifdef _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "azure_c_shared_utility/gballoc.h"
#include "application.h"

#include <time.h>
#include "azure_c_shared_utility/agenttime.h"

time_t get_time(time_t* p)
{
  struct tm my_time;
  time_t result;
  char temp_buffer[256];
  
  my_time.tm_hour = Time.hour();
  my_time.tm_min = Time.minute();
  my_time.tm_sec = Time.second();
  my_time.tm_mon = Time.month() - 1;
  my_time.tm_mday = Time.day();
  my_time.tm_year = Time.year() - 1900;

  result = mktime(&my_time);
  if (p != NULL)
  {
    *p = result;
  }

    return result;
}

struct tm* get_gmtime(time_t* currentTime)
{
    return gmtime(currentTime);
}

char* get_ctime(time_t* timeToGet)
{
    return ctime(timeToGet);
}

double get_difftime(time_t stopTime, time_t startTime)
{
    return difftime(stopTime, startTime);
}
