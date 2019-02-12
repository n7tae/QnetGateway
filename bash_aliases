# Copyright (c) 2019 by Thomas A. Early N7TAE

# copy this to ~/.bash_aliases if you don't want to use qnadmin to start and stop QnetGateway

function start () {
	if [ -n "$1" ]; then
		sudo make installbase && sudo make install${1} && sudo journalctl -u qn${1} -f
	else
		echo "usage: start module_name"
	fi
}

function stop () {
	if [ -n "$1" ]; then
		sudo make uninstallbase && sudo make uninstall${1}
	else
		echo "usage: stop module_name"
}

function watch () {
	if [ -n "$1" ]; then
		sudo journalctl -u ${1} -f
	else
		echo "usage: watch service_name"
	fi
}
