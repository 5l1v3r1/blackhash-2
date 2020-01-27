PREFIX		= /usr
SBINDIR		= $(PREFIX)/bin
PROJECT		= blackhash
INC			= -Iinc
LIB			= -lcryptopp -lpthread
SRC			= src
OBJ			= $(SRC)/main.o
CXXFLAGS	= -O2 -std=c++11 -Wall -Wextra $(INC) $(LIB)


all: $(PROJECT)

$(SRC)%.o: %.cpp
	$(CXX) -c -o $@ $< $(CXXFLAGS)

$(PROJECT): $(OBJ)
	$(CXX) -o $@ $^ $(CXXFLAGS)

.PHONY: clean

clean:
	rm -f $(SRC)/*.o *~ core $(PROJECT)

install: $(PROJECT)
	install -Dm 755 $(PROJECT) $(DESTDIR)/$(SBINDIR)/$(PROJECT)

uninstall:
	rm -f $(DESTDIR)/$(SBINDIR)/$(PROJECT)