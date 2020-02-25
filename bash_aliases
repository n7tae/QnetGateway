# Copyright (c) 2019 by Thomas A. Early N7TAE

# copy this to ~/.bash_aliases if you don't want to use qnadmin to start and stop QnetGateway

function start () {
	if [ $# == 1 ]; then
		sudo make installbase && sudo make install${1} && sudo journalctl -u qn${1} -f
	elif [ $# == 2 ]; then
		sudo make installbase && sudo make install${1} && sudo journalctl -u qn${2} -f
	else
		echo "Usage: start module_name [watch_module]"
		echo "Installs the base system and the module_name prefixed with 'qn' and tails the log."
		echo "Use watch_module if you want to tail a different log"
		echo "Only use this alias for systems with a single defined module."
		echo "You must be in the QnetGateway build directory"
	fi
}

function stop () {
	if [ $# == 1 ]; then
		sudo make uninstallbase && sudo make uninstall${1}
	else
		echo "usage: stop module_name"
		echo "Uninstalls the base system and the module_name prefixed with 'qn'."
		echo "Use this alias on for systems with a single defined module."
	fi
}

function watch () {
	if [ $# == 1 ]; then
		sudo journalctl -u qn${1} -f
	else
		echo "usage: watch service_name"
		echo "Tails the log from the service_name prefixed with 'qn'."
	fi
}
