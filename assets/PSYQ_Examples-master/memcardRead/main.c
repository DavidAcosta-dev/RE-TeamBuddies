/*
 * Written By: John Convertino
 * 
 * Memory Card Read example, will read the phrase written my the memcardWrite example.
 * 
 */

#include "engine.h"

int main() 
{
  char *p_title = "Memory Card Read Example\nREAD:";
  struct s_environment environment;
  
  initEnv(&environment, 0);
  
  environment.envMessage.p_title = p_title;
  environment.envMessage.p_message = memoryCardRead(128);
  environment.envMessage.p_data = (int *)&environment.gamePad.one;

  for(;;)
  {
    display(&environment);
  }

  return 0;
}
