#!/usr/bin/env python3
# modules/step28_proto_pollution.py — Prototype Pollution Engine
# FIX BUG-06: Added missing module so proto_pollution step can run
# MilkyWay Intelligence | Author: Sharlix

from engines.proto_pollution import ProtoPollutionEngine


class Step28ProtoPollution:
    def __init__(self, pipeline):
        self.p = pipeline

    def run(self):
        self.p.log.info("Prototype Pollution: using V7 async engine")
        ProtoPollutionEngine(self.p).run()
