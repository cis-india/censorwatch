# CensorWatch

This repository hosts the website for CensorWatch (CIS' project to map net neutrality violations and web censorship in India), the data collected through the project and the scripts used to analyse the data

To download the data, visit the [Releases](https://github.com/cis-india/censorwatch/releases/tag/1.0.0) section of this repository.

To import the data (using Mongo DB), extract the zip archive and inside the directory run `mongorestore --db log_database`.

To analyse the data (using R), see the `analysis_scripts` directory. `connect.R` and `query1.R` are useful starting points.

If you the use this data, please consider citing the paper [CensorWatch: On the Implementation of Online Censorship in India](https://www.petsymposium.org/foci/2023/foci-2023-0006.php).
