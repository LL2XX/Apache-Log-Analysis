test: clean test.o Log-Analysis.o IPLocator.o
	g++ test.o Log-Analysis.o IPLocator.o -o test

test.o: test.cpp
	g++ -c test.cpp

Log-Analysis.o: ../libLogAnalysis/Log-Analysis.cpp
	g++ -c ../libLogAnalysis/Log-Analysis.cpp

IPLocator.o: ../libLogAnalysis/IPLocator.cpp
	g++ -c ../libLogAnalysis/IPLocator.cpp

test-install: clean test-install.cpp
	g++ -o test-install test-install.cpp -L./ -lLogAnalysis

clean:
	if [ -e test-install ] ; then rm test-install ; fi
	if [ -e test ] ; then rm test ; fi
	if [ -e test.o ] ; then rm *.o ; fi
