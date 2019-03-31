# Name: Angus Hudson
# Student ID: 835808
# Login ID: a.hudson1/ahudson1

certcheck: certcheck.c
	gcc certcheck.c -o certcheck -lssl -lcrypto
clean:
	rm certcheck
