"""Validate a collector Turtle export against the merged Corona ontologies."""

import argparse
from pathlib import Path

from pyshacl import validate
from rdflib import Graph, Namespace, RDF, URIRef


NETWORK = Namespace("http://www.example.org/network-ontology#")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("topology", type=Path, help="Turtle file from --corona")
    parser.add_argument("--network-ontology", required=True, type=Path)
    parser.add_argument("--network-shapes", required=True, type=Path)
    parser.add_argument("--metrics-ontology", type=Path)
    parser.add_argument("--metrics-shapes", type=Path)
    args = parser.parse_args()
    if bool(args.metrics_ontology) != bool(args.metrics_shapes):
        parser.error("--metrics-ontology and --metrics-shapes must be supplied together")

    data = Graph().parse(args.topology, format="turtle")
    network_ontology = Graph().parse(args.network_ontology, format="turtle")
    ontology = Graph()
    ontology += network_ontology
    shapes = Graph().parse(args.network_shapes, format="turtle")
    if args.metrics_ontology:
        ontology += Graph().parse(args.metrics_ontology, format="turtle")
        shapes += Graph().parse(args.metrics_shapes, format="turtle")

    used = {
        predicate
        for _, predicate, _ in data
        if str(predicate).startswith(str(NETWORK))
    }
    used.update(
        value
        for _, predicate, value in data
        if predicate == RDF.type
        and isinstance(value, URIRef)
        and str(value).startswith(str(NETWORK))
    )
    defined = {subject for subject, _, _ in network_ontology}
    undefined = sorted(used - defined, key=str)
    if undefined:
        parser.exit(1, "Undefined network terms: " + ", ".join(map(str, undefined)) + "\n")

    conforms, _, report = validate(
        data, shacl_graph=shapes, ont_graph=ontology, inference="rdfs"
    )
    if not conforms:
        parser.exit(1, str(report) + "\n")
    print(f"Corona topology valid: {len(data)} triples, {len(used)} defined network terms")


if __name__ == "__main__":
    main()
