
OCC=ocamlc -I +unix -I +str
OCN=ocamlopt -I +unix -I +str
OCA=ocamlc -a -I +unix -I +str
OCAN=ocamlopt -a -I +unix -I +str
TOP=ocamlmktop -I +unix -I +str 
ML=ipc.ml
MLI=ipc.mli
CMO=$(subst ml,cmo,$(ML))
CMX=$(subst ml,cmx,$(ML))
CMA=$(subst ml,cma,$(ML))
CMXA=$(subst ml,cmxa,$(ML))

CMAA=unix.cma str.cma $(CMA)

all:  libcIpc.a ipc.cma ipc.cmxa ipc.cmi ipc.top

%.top:  $(CMO)
	$(TOP) -custom -o ipc.top $(CMAA)

%.cma:  $(CMO)
	$(OCA) -o $(CMA) -ccopt -L. -cclib -lcIpc $+

%.cmxa:  $(CMX)
	$(OCAN) -o $(CMXA) -ccopt -L. -cclib -lcIpc $+

%.cmo:  %.ml
	$(OCC) -c $<i
	$(OCC) -c $<
	$(OCN) -c $<

%.cmx:  %.ml
	$(OCC) -c $<i
	$(OCC) -c $<
	$(OCN) -c $<

libcIpc.a:  cIpc.o
	ar rcs $@ $+

cIpc.o:  cIpc.c
	$(OCC) -c -o cIpc.o cIpc.c

clean:  *.o *.a *.cm?
	rm *.o *.a *.cm?
