===========================================================
j4sign - an open, multi-platform digital signature solution
===========================================================

1. BUILD
For building, you have download and install Ant, the make utility
for java projects; http://ant.apache.org .

Building requires to setup in your home directory 
a keystore named .keystore.swsign, which contains the RSA
keys needed to sign jars. 
An howto is available on the j4sign wiki for creating the signing keystore:

http://sourceforge.net/apps/trac/j4sign/wiki/HowtoSignCode_en

See buildfile (build.xml) for details.

From inside of the j4sign src distribution root, run: 

<ANT_HOME>\bin\ant

where <ANT_HOME> is the home of your Ant installation;
this builds a binary distibution of j4sign.

2. RUN
You have to add the "bin" directory of your Java runtime
to the current PATH, so that the java

From inside the root of your j4sign binary distribution,
run (with administration rights) first the install.bat 
(or install.sh in unix environments) script for installing 
the java extension and the related native libraries.

In order to do full verification of signatures, you have
to download the signed package of root CA certificates from:

http://www.cnipa.gov.it/site/_files/lista%20dei%20certificati.html

and place it inside the "conf" directory along with "DigitPA.cer", 
the root certificate for the signing certificate of the package.
Then modify accordingly the package name in the conf.properties file. 

Run the runcli.bat (or runcli.sh in unix environments)
to start the CLI example, which tests the signature and verification process.
You can skip the signature part (if you do not have a signature device, 
for instance) providing a CAdES signed file as parameter. Only verification
will be performed.

The applet-servlet example is deprecated. You have to build yourself 
the sc.war using the "web" ant target, and put it in a servlet container.
Please, note that this example is deprecated, is not in the binary distribution, 
and will be removed in future releases.

There is also a very basic GUI example for displaying and 
signing text only files.

3. LICENSE
j4sign software is covered by GNU GPL License.
Licenses for prerequisite components (pkcs11 wrapper, pcsc wrapper,
BouncyCastle libraries) are in the root directory for the binary 
distribution, and in the src directory for the source distribution.
