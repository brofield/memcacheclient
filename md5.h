/**
*  Id: md5.h,v 1.2 2006/03/03 15:04:49 tomas Exp 
*  Hash function MD5
*  @author  Roberto Ierusalimschy
*  Source:  http://www.keplerproject.org/md5/
*  Licence: MIT style
*/


#ifndef md5_h
#define md5_h

#define MD5_HASHSIZE       16

#ifdef __cplusplus
extern "C" {
#endif
    
extern void md5 (const char *message, long len, char *output);

#ifdef __cplusplus
}
#endif

#endif
