PROC=findcrypt
O1=consts
O2=sparse
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)consts$(O)  : $(I)llong.hpp $(I)pro.h consts.cpp findcrypt.hpp
$(F)findcrypt$(O): $(I)area.hpp $(I)auto.hpp $(I)bytes.hpp $(I)fpro.h        \
	          $(I)funcs.hpp $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp     \
	          $(I)lines.hpp $(I)llong.hpp $(I)loader.hpp $(I)moves.hpp  \
	          $(I)nalt.hpp $(I)name.hpp $(I)netnode.hpp $(I)pro.h       \
	          $(I)segment.hpp $(I)sistack.hpp $(I)ua.hpp $(I)xref.hpp   \
	          findcrypt.cpp findcrypt.hpp
$(F)sparse$(O)  : $(I)llong.hpp $(I)pro.h findcrypt.hpp sparse.cpp
