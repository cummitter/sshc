#!/usr/bin/bash

SCRIPT_DIR=`dirname "$(realpath ${BASH_SOURCE:-$0})"`
py=$(/usr/bin/which python3)

if [[ -z $py ]]
then
        echo "No python3 binary available, install one through the package manager of your system"
        exit;
else
        echo "Found python executable - $py"
fi

mkdir -vp $SCRIPT_DIR/config
mkdir -vp $SCRIPT_DIR/config/from_scripts
mkdir -vp $SCRIPT_DIR/config/to_scripts

# Just in case, check if keyring and gnupg are already present in the system
$py -c 'import keyring'
if [ $? == 0 ]
then
	KEYRING=1
else
	KEYRING=0
fi

$py -c 'import gnupg'
if [ $? == 0 ]
then
	GNUPG=1
else
	GNUPG=0
fi

if [ GNUPG == 1 ] && [ KEYRING == 1 ]
then
	echo "All dependencies are already found to be available in the global environment
	You can use the following command to start the program - $py $SCRIPT_DIR/sshc.py"
	exit
fi

$py -c 'import venv'
if [ $? == 0 ]
then
	$py -m venv $SCRIPT_DIR/config/venv
	pyv="$SCRIPT_DIR/config/venv/bin/python3"
	if [ -e $pyv ]
	then
		$pyv -c 'import keyring'
		if [ $? == 0 ]
		then
			echo '"keyring" module is already installed in the virtual environment'
			KEYRINGV=1
		else
			echo '"keyring" module is not found in the virtual environment, trying to install it'
			$pyv -m pip install keyring
			$pyv -c 'import keyring' || echo '"keyring" was not successfully installed'
		fi

		$pyv -c 'import gnupg'
		if [ $? == 0 ]
		then
			echo '"gnupg" module is already installed in the virtual environment'
			GNUPGV=1
		else
			echo '"gnupg" module is not found in virtual environment, trying to install it'
			$pyv -m pip install python-gnupg
			$pyv -c 'import gnupg' || echo '"gnupg" was not successfully installed'
		fi
	fi
else
	echo '"venv" module is not available for python3. If you wish for the dependencies to be installed in an isolated environment, install python3-venv through the package manager of your system
	If such option is not available, the dependencies are not necessary to run the program but are more likely to be available through pip (python3 -m pip install) or your package manager:
	1. python3-gnupg for encrypting/decrypting the file with potentially sensetive data of connection details to different hosts
	2. python3-keyring to securely store the decryption key for the same file if any will be found available
	
	You can use the following command to start the program - $py $SCRIPT_DIR/sshc.py'
	exit
fi

if [ GNUPGV == 1 ] && [ KEYRINGV == 1 ]
then
	echo "All dependencies are already or were installed in the virtual enviroment
	You can use the following command to start the program - $pyv $SCRIPT_DIR/sshc.py
	But even if you will use the default interpreter, the program will try to locate venv"
	exit
fi
