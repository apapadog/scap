all:
	cd scap_module; make
	cd libscap; make
	cd apps; make

clean:
	cd scap_module; make clean
	cd libscap; make clean
	cd apps; make clean

