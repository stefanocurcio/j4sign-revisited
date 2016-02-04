#!/bin/bash
# Check the java environment
if [ ! -x "$JAVA_HOME"/bin/java ]; then
  echo "Cannot find java command"
  echo "Check if you have defined the JAVA_HOME environment variable!"
  exit 1
fi

$JAVA_HOME/bin/java -cp lib/j4sign-core.jar:lib/bcmail-jdk16-145.jar:lib/bcprov-jdk16-145.jar it.trento.comune.j4sign.examples.GUITest $1

