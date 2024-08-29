NAME_OF_DOC ="thesis"

all: 
	latexmk -pdf -output-directory=build $(NAME_OF_DOC).tex 
	mv ./build/$(NAME_OF_DOC).pdf ./$(NAME_OF_DOC).pdf 
clean: 	
	rm -f *.aux *.log *.out *.pdf *.xml *.gz *bib *.bbl *.blg *.fdb_latexmk *.fls *.bcf *.lof *.lot *.toc
	rm -rf build $(NAME_OF_DOC).pdf

