/* 

   libavl.h

   definitions for balanced binary tree and prefix database

*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>


/* avl definitions -----------------------------------------------*/


enum AVLRES { ERROR, OK, BALANCE};

enum AVLSKEW {NONE, LEFT, RIGHT };

struct avldata {
  void *payload ;
  enum AVLSKEW skew;
  struct avldata *left, *right;  
  } ;

typedef struct avldata  avl_data ;
typedef avl_data       *avl_ptr ;
typedef avl_ptr        *avl_ref ;

extern int              avlinserted ;
extern avl_ptr          avl_inserted;

typedef int CMP(avl_ptr, avl_ptr);
typedef void AVLWORKER(avl_ptr, FILE *, int);

extern enum AVLRES avlinsert(avl_ref, avl_ptr, CMP *) ;
extern enum AVLRES avlremove(avl_ref, avl_ptr, CMP *) ;
extern avl_ptr avlaccess(avl_ptr, avl_ptr key, CMP *) ;
extern void avldepthfirst(avl_ptr, AVLWORKER *, FILE *, int);

