#
#
#

INCS=	audit.h								\
	audit_kernel.h							\
	audit_kevents.h							\
	audit_record.h							\
	audit_uevents.h

TARGET=	${DESTDIR}/usr/include/bsm

default:
clean:

install:
	mkdir -p -m 0755 ${TARGET}
	install -o root -g wheel -m 0644 ${INCS} ${TARGET}

