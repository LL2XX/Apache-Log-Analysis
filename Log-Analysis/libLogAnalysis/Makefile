libLogAnalysis.so: Log-Analysis.o libIPLocator.a
	g++ -shared Log-Analysis.o -L./ -lIPLocator -o libLogAnalysis.so
	sudo cp libLogAnalysis.so /usr/local/lib
	sudo cp libLogAnalysis.so /usr/lib

Log-Analysis.o: Log-Analysis.cpp
	g++ -c -fPIC Log-Analysis.cpp

libIPLocator.a: IPLocator.o
	ar -r libIPLocator.a IPLocator.o
	sudo cp libIPLocator.a /usr/local/lib/

IPLocator.o: IPLocator.cpp
	g++ -c -fPIC IPLocator.cpp

install: clean libLogAnalysis.so

clean:
	if [ -e *.a ] ; then rm *.a ; fi
	if [ -e *.so ] ; then rm *.so ; fi
	if [ -e IPLocator.o ] ; then rm IPLocator.o ; fi
	if [ -e Log-Analysis.o ] ; then rm Log-Analysis.o ; fi
