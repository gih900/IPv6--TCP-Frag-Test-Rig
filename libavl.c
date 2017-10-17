#include "libavl.h"

/*************************************************
 *  avlrotleft: perform counterclockwise rotation
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node
 */

void
avlrotleft(avl_ref n)
{
  avl_ptr tmp = *n;

  *n = (*n)->right;
  tmp->right = (*n)->left;
  (*n)->left = tmp;
}

/*************************************************
 *
 *  avlrotright: perform clockwise rotation
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node
 */

void
avlrotright(avl_ref n)
{
  avl_ptr tmp = *n;

  *n = (*n)->left;
  tmp->left = (*n)->right;
  (*n)->right = tmp;
}

/*************************************************
 *
 *  avlleftgrown: helper function for avlinsert
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node. This node's left 
 *                subtree has just grown due to item insertion; its 
 *                "skew" flag needs adjustment, and the local tree 
 *                (the subtree of which this node is the root node) may 
 *                have become unbalanced.
 *
 *  Return values:
 *
 *    OK          The local tree could be rebalanced or was balanced 
 *                from the start. The parent activations of the avlinsert 
 *                activation that called this function may assume the 
 *                entire tree is valid.
 *
 *    BALANCE     The local tree was balanced, but has grown in height.
 *                Do not assume the entire tree is valid.
 */

enum AVLRES
avlleftgrown(avl_ref n)
{
  switch ((*n)->skew) {
    case LEFT:
      if ((*n)->left->skew == LEFT) {
        (*n)->skew = (*n)->left->skew = NONE;
        avlrotright(n);
        }        
      else {
        switch ((*n)->left->right->skew) {
          case LEFT:
            (*n)->skew = RIGHT;
            (*n)->left->skew = NONE;
            break;
                     
          case RIGHT:
            (*n)->skew = NONE;
            (*n)->left->skew = LEFT;
            break;

          default:
            (*n)->skew = NONE;
            (*n)->left->skew = NONE;
          }
        (*n)->left->right->skew = NONE;
        avlrotleft(& (*n)->left);
        avlrotright(n);
        }
      return OK;

    case RIGHT:
      (*n)->skew = NONE;
      return OK;
        
    default:
      (*n)->skew = LEFT;
      return BALANCE;
    }
}

/*************************************************
 *
 *  avlrightgrown: helper function for avlinsert
 *
 *  See avlleftgrown for details.
 */

enum AVLRES
avlrightgrown(avl_ref n)
{
        switch ((*n)->skew) {
        case LEFT:                                        
                (*n)->skew = NONE;
                return OK;

        case RIGHT:
                if ((*n)->right->skew == RIGHT) {        
                        (*n)->skew = (*n)->right->skew = NONE;
                        avlrotleft(n);
                }
                else {
                        switch ((*n)->right->left->skew) {
                        case RIGHT:
                                (*n)->skew = LEFT;
                                (*n)->right->skew = NONE;
                                break;
                        
                        case LEFT:
                                (*n)->skew = NONE;
                                (*n)->right->skew = RIGHT;
                                break;

                        default:
                               (*n)->skew = NONE;
                               (*n)->right->skew = NONE;
                        }
                        (*n)->right->left->skew = NONE;
                        avlrotright(& (*n)->right);
                        avlrotleft(n);
                }
                return OK;

        default:
                (*n)->skew = RIGHT;
                return BALANCE;
        }
}

/*************************************************
 *
 *  avlinsert: insert a node into the AVL tree.
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node.
 *
 *    d           Item to be inserted.
 *
 *  Return values:
 *
 *    nonzero     The item has been inserted. The exact value of 
 *                nonzero yields is of no concern to user code; when
 *                avlinsert recursively calls itself, the number 
 *                returned tells the parent activation if the AVL tree 
 *                may have become unbalanced; specifically:
 *
 *      OK        None of the subtrees of the node that n points to 
 *                has grown, the AVL tree is valid.
 *
 *      BALANCE   One of the subtrees of the node that n points to 
 *                has grown, the node's "skew" flag needs adjustment,
 *                and the AVL tree may have become unbalanced.
 *
 *    zero        The datum provided could not be inserted, either due 
 *                to AVLKEY collision (the tree already contains another
 *                item with which the same AVLKEY is associated), or
 *                due to insufficient memory.
 */   

int     avlinserted ;
avl_ptr avl_inserted;

enum AVLRES
avlinsert(avl_ref n, avl_ptr d, CMP *ac)
{
  enum AVLRES tmp;
  int compare ;

  if (!(*n)) {
    if (!((*n) =(avl_ptr) malloc(sizeof(struct avldata)))) {
      return ERROR;
      }
    (*n)->left = (*n)->right = NULL;
    (*n)->skew = NONE;
    (*n)->payload = d->payload;
    avl_inserted = (*n);
    avlinserted = 1 ;
    return BALANCE;
    }
  compare = (*ac)(d,(*n));

  if (compare < 0) {
    if ((tmp = avlinsert(& (*n)->left, d, ac)) == BALANCE) {
      return avlleftgrown(n);
      }
    return tmp;
    }
  if (compare > 0) {
    if ((tmp = avlinsert(& (*n)->right, d, ac)) == BALANCE) {
      return avlrightgrown(n);
      }
    return tmp;
    }
  avl_inserted = (*n);
  avlinserted = 0 ;
  return ERROR;
}   



/*************************************************
 *
 *  avlleftshrunk: helper function for avlremove and avlfindlowest
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node. The node's left
 *                subtree has just shrunk due to item removal; its
 *                "skew" flag needs adjustment, and the local tree
 *                (the subtree of which this node is the root node) may
 *                have become unbalanced.
 *
 *   Return values:
 *
 *    OK          The parent activation of the avlremove activation
 *                that called this function may assume the entire
 *                tree is valid.
 *
 *    BALANCE     Do not assume the entire tree is valid.
 */                

enum AVLRES
avlleftshrunk(avl_ref n)
{
  switch ((*n)->skew) {
    case LEFT:
                (*n)->skew = NONE;
                return BALANCE;

    case RIGHT:
                if ((*n)->right->skew == RIGHT) {
                        (*n)->skew = (*n)->right->skew = NONE;
                        avlrotleft(n);
                        return BALANCE;
                }
                else if ((*n)->right->skew == NONE) {
                        (*n)->skew = RIGHT;
                        (*n)->right->skew = LEFT;
                        avlrotleft(n);
                        return OK;
                }
                else {
                        switch ((*n)->right->left->skew) {
                        case LEFT:
                                (*n)->skew = NONE;
                                (*n)->right->skew = RIGHT;
                                break;

                        case RIGHT:
                                (*n)->skew = LEFT;
                                (*n)->right->skew = NONE;
                                break;

                        default:
                                (*n)->skew = NONE;
                                (*n)->right->skew = NONE;
                        }
                        (*n)->right->left->skew = NONE;
                        avlrotright(& (*n)->right);
                        avlrotleft(n);
                        return BALANCE;
                }

    default:
                (*n)->skew = RIGHT;
                return OK;
    }
}

/*************************************************
 *
 *  avlrightshrunk: helper function for avlremove and avlfindhighest
 *
 *  See avlleftshrunk for details.
 */

enum AVLRES
avlrightshrunk(avl_ref n)
{
  switch ((*n)->skew) {
    case RIGHT:
      (*n)->skew = NONE;
      return BALANCE;

    case LEFT:
      if ((*n)->left->skew == LEFT) {
        (*n)->skew = (*n)->left->skew = NONE;
        avlrotright(n);
        return BALANCE;
        }
      else if ((*n)->left->skew == NONE) {
        (*n)->skew = LEFT;
        (*n)->left->skew = RIGHT;
        avlrotright(n);
        return OK;
        }
      else {
        switch ((*n)->left->right->skew) {
          case LEFT:
            (*n)->skew = RIGHT;
            (*n)->left->skew = NONE;
            break;

          case RIGHT:
            (*n)->skew = NONE;
            (*n)->left->skew = LEFT;        
            break;
                        
          default:
            (*n)->skew = NONE;
            (*n)->left->skew = NONE;
          }
        (*n)->left->right->skew = NONE;
        avlrotleft(& (*n)->left);
        avlrotright(n);
        return BALANCE;
        }

    default:
      (*n)->skew = LEFT;
      return OK;
    }
}

/*************************************************
 *
 *  avlfindhighest: replace a node with a subtree's highest-ranking item.
 *
 *  Parameters:
 *
 *    target      Pointer to node to be replaced.
 *
 *    n           Address of pointer to subtree.
 *
 *    res         Pointer to variable used to tell the caller whether
 *                further checks are necessary; analog to the return
 *                values of avlleftgrown and avlleftshrunk (see there). 
 *
 *  Return values:
 *
 *    1           A node was found; the target node has been replaced.
 *
 *    0           The target node could not be replaced because
 *                the subtree provided was empty.
 *
 */

int
avlfindhighest(avl_ptr target, avl_ref n, enum AVLRES *res)
{
  avl_ptr tmp ;

  *res = BALANCE;
  if (!(*n)) {
    return 0;
    }
  if ((*n)->right) {
    if (!avlfindhighest(target, &(*n)->right, res)) {
      return 0;
      }
    if (*res == BALANCE) {
      *res = avlrightshrunk(n);
      }
    return 1;
    }
  target->payload = (*n)->payload ;
  tmp = *n;
  *n = (*n)->left;
  free(tmp);
  return 1;
}

/*************************************************
 *
 *  avlfindlowest: replace node with subtree's lowest-ranking item.
 *
 *  See avlfindhighest for the details.
 */

int
avlfindlowest(avl_ptr target, avl_ref n, enum AVLRES *res)
{
  avl_ptr tmp ;

  *res = BALANCE;
  if (!(*n)) {
    return 0;
    }
  if ((*n)->left) {
    if (!avlfindlowest(target, &(*n)->left, res)) {
      return 0;
      }
    if (*res == BALANCE) {
      *res =  avlleftshrunk(n);
      }
    return 1;
    }
  target->payload = (*n)->payload ;
  tmp = *n;
  *n = (*n)->right;
  free(tmp);
  return 1;
}

/*************************************************
 *
 *  avlremove: remove an item from the tree.
 *
 *  Parameters:
 *
 *    n           Address of a pointer to a node.
 *
 *    key         AVLKEY of item to be removed.
 *
 *  Return values:
 *
 *    nonzero     The item has been removed. The exact value of 
 *                nonzero yields if of no concern to user code; when
 *                avlremove recursively calls itself, the number
 *                returned tells the parent activation if the AVL tree
 *                may have become unbalanced; specifically:
 *
 *      OK        None of the subtrees of the node that n points to
 *                has shrunk, the AVL tree is valid.
 *
 *      BALANCE   One of the subtrees of the node that n points to
 *                has shrunk, the node's "skew" flag needs adjustment,
 *                and the AVL tree may have become unbalanced.
 *
 *   zero         The tree does not contain an item yielding the
 *                AVLKEY value provided by the caller.
 */
 
enum AVLRES
avlremove(avl_ref n,  avl_ptr key, CMP *cmp)
{
  enum AVLRES tmp = BALANCE;
  int compare ;


  if (!(*n)) {
    return ERROR;
    }
  if ((compare = (*cmp)(key,(*n))) < 0) {
    if ((tmp = avlremove(& (*n)->left, key, cmp)) == BALANCE) {
      return avlleftshrunk(n);
      }
    return tmp;
    }
  if (compare > 0) {
    if ((tmp = avlremove(& (*n)->right, key, cmp)) == BALANCE) {
      return avlrightshrunk(n);
      }
    return tmp;
    }
  if ((*n)->left) {
    if (avlfindhighest(*n, &((*n)->left), &tmp)) {
      if (tmp == BALANCE) {
        tmp = avlleftshrunk(n);
        }
      return tmp;
      }
    }
  if ((*n)->right) {
    if (avlfindlowest(*n, &((*n)->right), &tmp)) {
      if (tmp == BALANCE) {
        tmp = avlrightshrunk(n);
        }
      return tmp;
      }
    }
  free(*n);  
  *n = NULL;
  return BALANCE;
}   


/*************************************************
 *
 *  avlaccess: retrieve the datum corresponding to a given AVLKEY.
 *
 *  Parameters:
 *
 *    n     Pointer to the root node.
 *
 *    key   TKEY of item to be accessed.
 *
 *  Return values:
 *
 *    non-NULL    An item yielding the AVLKEY provided has been found,
 *    the return value points to the AVLKEY attached to it.
 *
 *    NULL  The item could not be found.
 */

avl_ptr
avlaccess(avl_ptr n, avl_ptr key, CMP *cmp)
{
  int compare;

  if (!n) {
    return NULL;
    }
  if ((compare = (*cmp)(key,n)) < 0) {
    return avlaccess(n->left, key, cmp);
    }
  if (compare > 0) {
    return avlaccess(n->right, key, cmp);
    }
  return(n);
}   


/*************************************************
 *
 *  Function to be called by the tree traversal functions.
 *
 *  Parameters:
 *
 *    n     Pointer to a node.
 *
 *    param       Value provided by the traversal function's caller.
 *
 *    depth       Recursion depth indicator. Allows the function to
 *    determine how many levels the node bein processed is
 *    below the root node. Can be used, for example,
 *    for selecting the proper indentation width when
 *    avldepthfirst is used to print a tree dump to 
 *    the screen.
 */

/*************************************************
 *
 *  avldepthfirst: depth-first tree traversal.
 *
 *  Parameters:
 *
 *    n    Pointer to the root node.
 *
 *    f    Worker function to be called for every node.
 *
 *    param      Additional parameter to be passed to the
 *         worker function
 *
 *    depth      Recursion depth indicator. Allows the worker function
 *         to determine how many levels the node being processed
 *         is below the root node. Can be used, for example,
 *         for selecting the proper indentation width when
 *         avldepthfirst ist used to print a tree dump to
 *         the screen.
 *
 *         Most of the time, you will want to call avldepthfirst
 *         with a "depth" value of zero.
 */

void
avldepthfirst(avl_ptr n, AVLWORKER *f, FILE *param, int depth)
{
  if (!n) return;
  avldepthfirst(n->left, f, param, depth + 1);
  (*f)(n, param, depth);
  avldepthfirst(n->right, f, param, depth + 1);
}   


/*************************************************
 */

int
avlbreadthfirst(avl_ptr n, int cdepth , AVLWORKER *f, FILE *param, int depth)
{  
  if (!n) return(0);
  if (cdepth > depth) {
    int i ;
    i  = avlbreadthfirst(n->left,  cdepth, f, param, depth + 1);
    i += avlbreadthfirst(n->right, cdepth, f, param, depth + 1);
    return(i) ;
    }
  if (cdepth == depth) {
    (*f)(n, param, depth);
    if (n->left || n->right) return(1);
    }
  return(0) ;
}

