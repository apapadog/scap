
all:
	gcc scap_test1.c ../libscap/scap.o -lpthread -D_GNU_SOURCE -o scap_test1
	gcc exp1.c ../libscap/scap.o -lpthread -D_GNU_SOURCE -o exp1
	gcc exp2.c ../libscap/scap.o -lpthread -D_GNU_SOURCE -o exp2
	gcc exp3.c ../libscap/scap.o acsmx.c -lpthread -D_GNU_SOURCE -o exp3
	gcc exp4.c ../libscap/scap.o acsmx.c -lpthread -D_GNU_SOURCE -o exp4
	gcc exp5.c ../libscap/scap.o acsmx.c -lpthread -D_GNU_SOURCE -o exp5

clean:
	rm -f scap_test1 exp1 exp2 exp3 exp4 exp5


