#!/usr/bin/env python3
"""The SuperNOVA 2 board: the SuperNOVA board, drawn with SuperNOVA 2's art.

Its tournaments come from live.json's "sn2_comps" once the gate publishes
them. Until then the board shows who is online and no tournaments, rather
than SuperNOVA's, whose song ids mean different songs on this disc.
"""
from boardsn import SnBoard

BOARD = SnBoard('sn2', 'DDR SuperNOVA 2', 'sn2_comps')
