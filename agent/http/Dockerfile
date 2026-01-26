FROM mwaeckerlin/mingw

# Définir le répertoire de travail
WORKDIR /workspace

# Copier les fichiers sources (optionnel - vous pouvez aussi monter un volume)
COPY . .

# Script de compilation par défaut
COPY compile.sh /usr/local/bin/compile.sh
RUN chmod +x /usr/local/bin/compile.sh

# Commande par défaut
CMD ["/bin/bash"]