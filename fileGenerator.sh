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
  extensionList+=("$extensions")
done < "$extensionsFile"

randomStringGen() {
  cat /dev/urandom | LC_ALL=C tr -dc 'a-zA-Z0-9' | fold -w 50 | head -n 1
}

for extension in "${extensionList[@]}"; do
  file=42$extension
  touch "$folder/$file"
  randomString=$(randomStringGen 10)
  echo "$randomString" >> "$folder/$file"
done

touch "$folder/00.ft"
touch "$folder/00.kk"
