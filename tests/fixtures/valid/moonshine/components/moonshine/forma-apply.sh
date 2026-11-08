#!/bin/sh
# Materia runs this as SetupScript and PostScript, while it holds its lock.
exec forma apply moonshine --materia-lock held
