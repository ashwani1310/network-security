#ifndef UTILITY_H
#define UTILITY_H


/* A wrapper method for perror.
 * It logs the error message and
 * terminates the process.
 */
void do_error(char *msg) {
	perror(msg);
	exit(1);
}

#endif
