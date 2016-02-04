/*
 * Copyright © 1997 - 1999 IBM Corporation.
 * 
 * Redistribution and use in source (source code) and binary (object code)
 * forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributed source code must retain the above copyright notice, this
 * list of conditions and the disclaimer below.
 * 2. Redistributed object code must reproduce the above copyright notice,
 * this list of conditions and the disclaimer below in the documentation
 * and/or other materials provided with the distribution.
 * 3. The name of IBM may not be used to endorse or promote products derived
 * from this software or in any other form without specific prior written
 * permission from IBM.
 * 4. Redistribution of any modified code must be labeled "Code derived from
 * the original OpenCard Framework".
 * 
 * THIS SOFTWARE IS PROVIDED BY IBM "AS IS" FREE OF CHARGE. IBM SHALL NOT BE
 * LIABLE FOR INFRINGEMENTS OF THIRD PARTIES RIGHTS BASED ON THIS SOFTWARE.  ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IBM DOES NOT WARRANT THAT THE FUNCTIONS CONTAINED IN THIS
 * SOFTWARE WILL MEET THE USER'S REQUIREMENTS OR THAT THE OPERATION OF IT WILL
 * BE UNINTERRUPTED OR ERROR-FREE.  IN NO EVENT, UNLESS REQUIRED BY APPLICABLE
 * LAW, SHALL IBM BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.  ALSO, IBM IS UNDER NO OBLIGATION
 * TO MAINTAIN, CORRECT, UPDATE, CHANGE, MODIFY, OR OTHERWISE SUPPORT THIS
 * SOFTWARE.
 */

/*
 * Author:  Stephan Breideneich (sbreiden@de.ibm.com)
 * Version: $Id: fieldIO.cpp,v 1.1 1998/04/07 11:14:19 breid Exp $
 */

#include <jni.h>
#include "fieldIO.h"

/*******************************************************************************
 * getIntField
 *
 * This function is used to get the contents of an integer field specified by
 * an object and a field name. An exception is thrown when something goes wrong.
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 * pFieldValue    - pointer to integer to contain field value
 *
 * Returns:
 * 0		  - everything OK
 * != 0		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
long getIntField(JNIEnv *env, jobject obj,  char *fieldName, long *pFieldValue) {
   long   rc = 1;
   jfieldID fid;

   // first get field ID, then value of field. The java functions will generate any
   // necessary exceptions.

   fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "I");
   if (fid != NULL) {
      *pFieldValue = env->GetIntField(obj, fid);
      if (env->ExceptionOccurred() == NULL) rc = 0;
   }

   return rc;
}


/*******************************************************************************
 * setIntField
 *
 * This function is used to set the contents of an integer field specified by
 * an object and a field name. An exception is thrown when something goes wrong.
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 * fieldValue     - integer value to be set
 *
 * Returns:
 * 0		  - everything OK
 * != 0		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
long setIntField(JNIEnv *env, jobject obj,  char *fieldName, long fieldValue) {
   long   rc = 1;
   jfieldID fid;

   // first get field ID, then set value of field. The java functions will generate
   // any necessary exceptions.

   fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "I");
   if (fid != NULL) {
      env->SetIntField(obj, fid, fieldValue);
      if (env->ExceptionOccurred() == NULL) rc = 0;
   }

   return rc;
}


/*******************************************************************************
 * accessByteArray
 *
 * This function provides C access to a byte array field of the specified name
 * contained in an object.
 *
 * Arrays accessed through this function must be released through the
 * releaseByteArray function.
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 * field	  - (output) pointer to pointer to byte array
 * size		  - (output) size of the byte array.
 *
 * Returns:
 * 0		  - no error
 * != 0		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
long accessByteArray(JNIEnv *env,
		    jobject obj,
		    char *fieldName,
		    unsigned char **field,
		    int *pSize) {

   unsigned char  *pByte=NULL;
   jfieldID       fid;
   jbyteArray     jba;
   long		  error=1;

   // first get field ID, then value of field. The java functions will generate any
   // necessary exceptions.

   fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "[B");
   if (fid != NULL) {
      jba = (jbyteArray)env->GetObjectField(obj, fid);
      if (env->ExceptionOccurred() == NULL) {
	 if (jba == NULL) {
	    *pSize = 0;
	    error = 0;
	 } else {
	    *pSize = (int)env->GetArrayLength(jba);
	    pByte = (unsigned char*)env->GetByteArrayElements(jba, 0);
	    if (env->ExceptionOccurred() == NULL) error=0;
	 }							   /* endif*/
      }								   /* endif*/
   }								   /* endif*/

   *field = pByte;
   return error;
}


/*******************************************************************************
 * releaseByteArray
 *
 * This function releases access to the java byte array buffer pointed to
 * by the input pointer. The byte array whose buffer is being released is
 * a byte array field of an object specifed by obj and fieldName.
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 * pByte	  - buffer to be released
 *
 * Returns:
 * 0		  - OK
 * !=0		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
long releaseByteArray(JNIEnv *env, jobject obj,  char *fieldName, unsigned char *pByte) {

   long	       rc=1;
   jfieldID    fid;
   jbyteArray  jba;

   // first get field ID, then value of field. The java functions will generate any
   // necessary exceptions.

   if (pByte == NULL) rc=0;
   else {
      fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "[B");
      if (fid != NULL) {
	 jba = (jbyteArray)env->GetObjectField(obj, fid);
	 if (env->ExceptionOccurred() == NULL) {
	    env->ReleaseByteArrayElements(jba, (jbyte*)pByte, 0);
	    if (env->ExceptionOccurred() == NULL) rc =0;
	 }							   /* endif*/
      }								   /* endif*/
   }								   /* endif*/

   return rc;
}


/*******************************************************************************
 * accessStringField
 *
 * This function is used to get the contents of a string field specified by
 * an object and a field name. An exception is thrown when something goes wrong.
 *
 * The field must be released using releaseStringField!!
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 *
 * Returns:
 * != Null	  - everything OK, pointer to characters
 * NULL		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
const char *accessStringField(JNIEnv *env, jobject obj,  char *fieldName) {
   jfieldID    fid;
   jstring     jstr;
   const char  *pstr = NULL;

   // first get field ID, then value of field. The java functions will generate any
   // necessary exceptions.

   fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "Ljava/lang/String;");
   if (fid != NULL) {
      jstr = (jstring)env->GetObjectField(obj, fid);
      if (env->ExceptionOccurred() == NULL) {
	 pstr = env->GetStringUTFChars(jstr, 0);
      }								   /* endif*/
   }								   /* endif*/

   return pstr;
}


/*******************************************************************************
 * releaseStringField
 *
 * This function releases access to a java string.
 *
 * Parameters:
 * env		  - pointer to java environment
 * obj		  - designates object containing desired field
 * fieldName      - ASCIIZ string containing name of field
 * field	  - Java string field to be released
 *
 * Returns:
 * 0		  - everything OK, pointer to characters
 * != 0		  - problem occurred, exception was thrown
 *
 ******************************************************************************/
long releaseStringField(JNIEnv *env, jobject obj,  char *fieldName, const char *field) {
   jfieldID    fid;
   jstring     jstr;
   int	       error = 1;

   // first get field ID, then value of field. The java functions will generate any
   // necessary exceptions.

   fid = env->GetFieldID(env->GetObjectClass(obj), fieldName, "Ljava/lang/String;");
   if (fid != NULL) {
      jstr = (jstring)env->GetObjectField(obj, fid);
      if (env->ExceptionOccurred() == NULL) {
	 env->ReleaseStringUTFChars(jstr, field);
	 if (env->ExceptionOccurred() == NULL) error = 0;
      }								   /* endif*/
   }								   /* endif*/

   return error;
}

// $Log: fieldIO.cpp,v $
// Revision 1.1  1998/04/07 11:14:19  breid
// initial version.
//
