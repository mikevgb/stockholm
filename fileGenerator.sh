#!/bin/bash

folder="infection"

if [ ! -d "$folder" ]; then
  mkdir -p "$folder"
  if [ $? -ne 0 ]; then
    echo "Failed to create the folder"
    exit 1
  fi
fi

extensionsFile="extensions"
extensions=()

while IFS= read -r extensions; do
  extensions+=("$extensions")
done < "$extensionsFile"

for extension in "${extensions[@]}"; do
  touch "$folder/42$extension"
done
