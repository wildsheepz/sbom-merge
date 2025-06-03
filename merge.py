import sys
import json
import logging
import argparse
import subprocess
import shlex
import os
import hashlib
import traceback

sbom_cache = {}


class SPDXElement:
    def __init__(self, json_data, sbom):
        self.json_data = json_data
        if "hash" not in sbom:
            md5 = hashlib.md5()
            md5.update(json.dumps(sbom).encode("utf-8"))
            hash = md5.digest().hex()
            sbom["hash"] = hash
        hash = sbom.get("hash")
        if hash not in sbom_cache:
            sbom_cache[hash] = SPDX(sbom)
        self.sbom: SPDX = sbom_cache.get(hash)


class SPDXFile(SPDXElement):
    def __init__(self, json_data, sbom):
        super().__init__(json_data, sbom)

    @property
    def SPDXID(self):
        return self.json_data.get("SPDXID")

    @property
    def checksums(self):
        return self.json_data.get("checksums")

    def checksums_value(self, algorithm="SHA256"):
        checksum_of_algo = [
            x
            for x in self.json_data.get("checksums", {})
            if x.get("algorithm") == algorithm
        ]
        if checksum_of_algo:
            return checksum_of_algo[0].get("checksumValue")
        return None

    def __eq__(self, other):
        if not isinstance(other, SPDXFile):
            return False
        return self.SPDXID == other.SPDXID and self.sbom == other.sbom

    @property
    def fileName(self):
        return self.json_data.get("fileName")

    def belongs_to(self):
        return [
            x
            for x in self.sbom.relationships
            if x.relationshipType == "CONTAINS"
            and x.relatedSpdxElementId == self.SPDXID
        ]

    def other(self):
        return [
            x
            for x in self.sbom.relationships
            if x.relatedSpdxElementId == self.SPDXID and x.relationshipType == "OTHER"
        ]


class SPDXPackage(SPDXElement):
    def __init__(self, json_data, sbom):
        super().__init__(json_data, sbom)

    @property
    def SPDXID(self):
        return self.json_data.get("SPDXID")

    @property
    def versionInfo(self):
        return self.json_data.get("versionInfo")

    @property
    def name(self):
        return self.json_data.get("name")

    @property
    def filesAnalyzed(self):
        return self.json_data.get("filesAnalyzed")

    @property
    def sourceInfo(self):
        return self.json_data.get("sourceInfo")

    @property
    def supplier(self):
        return self.json_data.get("supplier")

    @property
    def originator(self):
        return self.json_data.get("originator")

    def depends_on(self):
        return [
            x
            for x in self.sbom.relationships
            if x.relatedSpdxElement == self.SPDXID
            and x.relationshipType == "DEPENDENCY_OF"
        ]

    def is_dependency_of(self):
        return [
            x
            for x in self.sbom.relationships
            if x.spdxElementId == self.SPDXID and x.relationshipType == "DEPENDENCY_OF"
        ]

    def __eq__(self, other):
        if not isinstance(other, SPDXPackage):
            return False
        return self.SPDXID == other.SPDXID and self.sbom == other.sbom


class SPDXRelationship(SPDXElement):
    def __init__(self, json_data, sbom):
        super().__init__(json_data, sbom)

    @property
    def spdxElement(self):
        return self.sbom.find_by_spdxid(self.spdxElementId)

    @property
    def spdxElementId(self):
        return self.json_data.get("spdxElementId")

    @property
    def relationshipType(self):
        return self.json_data.get("relationshipType")

    @property
    def relatedSpdxElementId(self):
        return self.json_data.get("relatedSpdxElement")

    @property
    def relatedSpdxElement(self):
        return self.sbom.find_by_spdxid(self.relatedSpdxElementId)

    @property
    def comment(self):
        return self.json_data.get("comment")


class SPDX:
    def __init__(self, json_data):
        self.json_data: dict[str, any] = json_data
        self._cache_relationships: list[SPDXRelationship] = None
        self._cache_packages: list[SPDXPackage] = None
        self._cache_files: list[SPDXFile] = None

    @property
    def packages(self) -> list[SPDXPackage]:
        if "packages" not in self.json_data:
            return []
        if not self._cache_packages:
            logging.debug("Generating packages cache")
            self._cache_packages = [
                SPDXPackage(x, self.json_data) for x in self.json_data.get("packages")
            ]
            logging.debug("Done: packages cache")
        return self._cache_packages

    @property
    def files(self) -> list[SPDXFile]:
        if "files" not in self.json_data:
            return []
        if not self._cache_files:
            logging.debug("Generating files cache")
            self._cache_files = []
            files_data = self.json_data.get("files")
            for idx, x in enumerate(files_data):
                if idx % 3000 == 0:
                    logging.debug(f"{idx}/{len(files_data)}")
                self._cache_files.append(SPDXFile(x, self.json_data))

            logging.debug("Done: files cache")
        return self._cache_files

    @property
    def relationships(self) -> list[SPDXRelationship]:
        if not self._cache_relationships:
            logging.debug("Generating relationship cache")
            self._cache_relationships = [
                SPDXRelationship(x, self.json_data)
                for x in self.json_data.get("relationships")
            ]
            logging.debug("Done: relationship cache")
        return self._cache_relationships

    def find_by_spdxid(self, spdx_id) -> [SPDXFile | SPDXPackage]:
        if spdx_id.startswith("SPDXRef-File"):
            for x in self.files:
                if x.SPDXID == spdx_id:
                    return x
        elif spdx_id.startswith("SPDXRef-Package"):
            for x in self.packages:
                if x.SPDXID == spdx_id:
                    return x
        return None

    def find_files_without_package(self):
        file_relationships_not_package: list[SPDXRelationship] = []
        for x in self.relationships:
            if x.spdxElement is None:
                continue
            is_generic_pkg = [
                y
                for y in x.spdxElement.json_data.get("externalRefs", {})
                if y.get("referenceLocator", "").startswith("pkg:generic")
            ]
            if (
                x.relationshipType == "CONTAINS"
                and x.relatedSpdxElementId.startswith("SPDXRef-File")
                and is_generic_pkg
            ):
                file_relationships_not_package.append(x)
            elif (
                x.relationshipType == "OTHER"
                and x.relatedSpdxElementId.startswith("SPDXRef-File")
                and is_generic_pkg
            ):
                file_relationships_not_package.append(x)

        return [x.relatedSpdxElement for x in file_relationships_not_package]


def spdx_id(data):
    return data.get("SPDXID")


def spdx_relationshipType(data):
    return data.get("relationshipType")


def find_one_in_array_by_key(array, key_name, key_value):
    if not array:
        return None
    for x in array:
        if x.get(key_name) == key_value:
            return x


def find_all_in_array_by_key(array, key_name, key_value):
    result = []
    for x in array:
        if x.get(key_name) == key_value:
            result.append(x)
    return result


def spdx_relationships(sbom_data, spdx_id, types=[]):
    all_relations = sbom_data.get("relationships")
    if types:
        return [
            x
            for x in find_all_in_array_by_key(
                all_relations, "relatedSpdxElement", spdx_id
            )
            if spdx_relationshipType(x) in types
        ]
    else:
        return find_all_in_array_by_key(all_relations, "relatedSpdxElement", spdx_id)


def merge_sboms_new(default, additionals):

    def inject(to_spdxFile: SPDXFile, from_spdxFile: SPDXFile):
        logging.info(f"Updating {to_spdxFile.fileName}")
        for relations in to_spdxFile.other():
            spdx_package = relations.spdxElement
            logging.debug(
                f"Removing Package Data: {json.dumps(spdx_package.json_data, indent=2)}"
            )
            try:
                to_spdxFile.sbom.json_data.get("packages", {}).remove(
                    spdx_package.json_data
                )
            except ValueError as e:
                if not str(e).endswith("x not in list"):
                    traceback.print_exc()
            logging.debug(
                f"Removing Relationship Data: {json.dumps(relations.json_data, indent=2)}"
            )
            try:
                to_spdxFile.sbom.json_data.get("relationships", {}).remove(
                    relations.json_data
                )
            except ValueError as e:
                if not str(e).endswith("x not in list"):
                    traceback.print_exc()
            for new_relationship in from_spdxFile.belongs_to():
                logging.debug(
                    f"Adding Relationship Data: {json.dumps(new_relationship.json_data, indent=2)}"
                )
                to_spdxFile.sbom.json_data.get("relationships").append(
                    new_relationship.json_data
                )
                if isinstance(new_relationship.spdxElement, SPDXPackage):
                    logging.debug(
                        f"Adding Package Data: {json.dumps(new_relationship.spdxElement.json_data, indent=2)}"
                    )
                    to_spdxFile.sbom.json_data.get("packages").append(
                        new_relationship.spdxElement.json_data
                    )

    def find_matching(spdxFile: SPDXFile, targetSpdx: SPDX):
        additional_spdxs: list[SPDX] = [SPDX(x) for x in additionals]
        for from_spdx in additional_spdxs:
            from_files = [x for x in from_spdx.files if x.fileName == spdxFile.fileName]
            if from_files:
                from_file: SPDXFile = from_files[0]
                if from_file.checksums_value() != spdxFile.checksums_value():
                    continue
                for from_package in from_file.belongs_to():
                    if not isinstance(from_package.spdxElement, SPDXPackage):
                        continue
                    filesAnalyzed = from_package.spdxElement.filesAnalyzed
                    if filesAnalyzed:
                        return from_file

    defaultSPDX = SPDX(default)

    logging.debug("checking files")
    all_files = defaultSPDX.find_files_without_package()
    for idx, spdxFile in enumerate(all_files):
        if idx % 10 == 0:
            logging.debug(f"checking files: {idx}/{len(all_files)}")
        matching = find_matching(spdxFile, defaultSPDX)
        if matching:
            inject(spdxFile, matching)
            continue
    return default


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s|%(levelname)s -- %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S %z",
)


def run(base_input):
    default = base_input.get("SPDX")
    additionals = [x for x in base_input.get("AdditionalSPDXs", {})]

    # Debugging write to file
    # open(".default-sbom.json", "w").write(json.dumps(default))
    # for idx, a in enumerate(additionals):
    #     open(f".additional-sbom{idx}.json", "w").write(json.dumps(a))

    result = merge_sboms_new(default, additionals)
    logging.info(f"Writing processed sbom to {args.output}")
    open(args.output, "w").write(json.dumps(result, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=str, required=True)
    parser.add_argument("--arch", type=str, default="linux/amd64", required=False)
    parser.add_argument(
        "--output", type=str, required=False, default="output-sbom.json"
    )
    parser.add_argument(
        "--output-raw", type=str, required=False, default="output-raw-sbom.json"
    )
    args, unknown = parser.parse_known_args()

    if unknown:
        logging.warn(f"unknown params are being ignored: {unknown}")

    cmd = (
        f"docker buildx imagetools inspect '{args.image}' --format "
        + "'{{ json .SBOM }}'"
    )
    proc = subprocess.Popen(
        shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = proc.communicate()
    return_code = proc.returncode
    proc.wait(30)
    response = "{}"
    if return_code == 0:
        response = stdout.decode()

    else:
        logging.error(stderr.decode())
        sys.exit(return_code)
    has_sbom = response != "{}" and len(response) > 0
    logging.info(f"Writing raw sbom to {args.output_raw}")
    open(args.output_raw, "w").write(response)
    input = json.loads(response)

    if has_sbom:
        if args.arch in input:
            # its a multi arch image
            spdx_input = input.get(args.arch, {})
        else:
            spdx_input = input

        is_supported_sbom_format = "SPDX" in spdx_input
        run(spdx_input)
    else:
        is_supported_sbom_format = False

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        logging.info(f"sbom-found={has_sbom}")
        logging.info(f"is-supported-format={is_supported_sbom_format}")
        gh_out = open(github_output, "a")
        gh_out.write(f"sbom-found={has_sbom}\n")
        gh_out.write(f"is-supported-format={is_supported_sbom_format}\n")
        gh_out.flush()
        gh_out.close()
