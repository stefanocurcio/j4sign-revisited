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
 * Version: $Id: fieldIO.h,v 1.1 1998/04/07 11:15:11 breid Exp $
 */

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
long getIntField(JNIEnv *, jobject,  char *, long *);


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
long setIntField(JNIEnv *, jobject,  char *, long);


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
long accessByteArray(JNIEnv *, jobject, char *, unsigned char **, int *);


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
long releaseByteArray(JNIEnv *, jobject,  char *, unsigned char *);


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
const char *accessStringField(JNIEnv *, jobject,  char *);


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
long releaseStringField(JNIEnv *, jobject,  char *, const char *);

// $Log: fieldIO.h,v $
// Revision 1.1  1998/04/07 11:15:11  breid
// initial version.
//
