# ELF Project

Projet d'étude du format ELF sous Linux, réalisé en C.

## Fonctionnalités

- Analyse de l'en-tête ELF.
- Affichage des segments et des sections.
- Calcul des correspondances entre adresses virtuelles et offsets.
- Étude et modification de chaînes dans un exécutable de test.

## Compilation

Compiler le projet avec :

    make

## Organisation

- `src/analyzer.c` : analyse des fichiers ELF.
- `src/elf_modifier.c` : étude et modification de chaînes.
- `tests/hello.c` : programme de test.
- `Makefile` : compilation du projet.
