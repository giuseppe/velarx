# SPDX-License-Identifier: Apache-2.0
# The file of the functions Aeneas has no model of, as ./run gives it to
# Lean: the template Aeneas writes (an `axiom` for each), without those
# the models of the crate define, which are imported instead.
#
#   awk -f externals.awk Models.lean FunsExternal_Template.lean
BEGIN { RS = ""; ORS = "\n\n" }
{ n = split($0, word, /[ \n]+/) }
NR == FNR {
    for (i = 1; i < n; i++)
        if (word[i] == "def")
            model[word[i + 1]]
    next
}
{
    for (i = 1; i < n; i++)
        if (word[i] == "axiom" && word[i + 1] in model)
            next
    sub(/public import Extracted.Types\n/, "&public import Models\n")
    print
}
