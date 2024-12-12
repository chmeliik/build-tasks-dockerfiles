#!/usr/bin/env python3
import json
from argparse import ArgumentParser
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Protocol, Sequence
from urllib.parse import quote_plus

from packageurl import PackageURL


def try_parse_purl(s: str) -> PackageURL | None:
    try:
        return PackageURL.from_string(s)
    except ValueError:
        return None


class SBOMItem(Protocol):
    def name(self) -> str: ...
    def version(self) -> str: ...
    def purl(self) -> PackageURL | None: ...
    def all_purls(self) -> list[PackageURL]: ...


@dataclass
class CDXComponent:
    data: dict[str, Any]

    def name(self) -> str:
        return self.data["name"]

    def version(self) -> str:
        return self.data.get("version") or ""

    def purl(self) -> PackageURL | None:
        if purl_str := self.data.get("purl"):
            return try_parse_purl(purl_str)
        return None

    def all_purls(self) -> list[PackageURL]:
        purl = self.purl()
        return [purl] if purl else []


def wrap_as_cdx(items: list[dict[str, Any]]) -> list[CDXComponent]:
    return list(map(CDXComponent, items))


def unwrap_from_cdx(items: list[CDXComponent]) -> list[dict[str, Any]]:
    return [c.data for c in items]


@dataclass
class SPDXPackage:
    data: dict[str, Any]

    def spdxid(self) -> str:
        return self.data["SPDXID"]

    def name(self) -> str:
        return self.data["name"]

    def version(self) -> str:
        return self.data.get("versionInfo") or ""

    def purl(self) -> PackageURL | None:
        purls = self.all_purls()
        if len(purls) > 1:
            self._verify_purl_similarity(purls)
        return purls[0] if purls else None

    def all_purls(self) -> list[PackageURL]:
        purls = [
            ref["referenceLocator"] for ref in self.data.get("externalRefs") or [] if ref["referenceType"] == "purl"
        ]
        return list(filter(None, map(try_parse_purl, purls)))

    def _verify_purl_similarity(self, purls: list[PackageURL]) -> None:
        # Verify that the purls for a single package are "similar enough" for the purposes of this script.
        # In practice, that means they need to be identical except for the qualifiers.
        # Beyond that, we'll trust cachi2 and syft not to group purls for unrelated packages.
        less_detailed_purls = set(purl._replace(qualifiers=None).to_string() for purl in purls)
        if len(less_detailed_purls) != 1:
            raise ValueError(f"The purls for an SPDX package are too different: {sorted(less_detailed_purls)}")


def wrap_as_spdx(items: list[dict[str, Any]]) -> list[SPDXPackage]:
    return list(map(SPDXPackage, items))


def unwrap_from_spdx(items: list[SPDXPackage]) -> list[dict[str, Any]]:
    return [c.data for c in items]


def _subpath_is_version(subpath: str) -> bool:
    # pkg:golang/github.com/cachito-testing/gomod-pandemonium@v0.0.0#terminaltor -> subpath is a subpath
    # pkg:golang/github.com/cachito-testing/retrodep@v2.1.1#v2 -> subpath is a version. Thanks, Syft.
    return subpath.startswith("v") and subpath.removeprefix("v").isdecimal()


def _is_syft_local_golang_component(component: SBOMItem) -> bool:
    """
    Check if a Syft Golang reported component is a local replacement.

    Local replacements are reported in a very different way by Cachi2, which is why the same
    reports by Syft should be removed.
    """
    purl = component.purl()
    if not purl or purl.type != "golang":
        return False
    if (subpath := purl.subpath) and not _subpath_is_version(subpath):
        return True
    return component.name().startswith(".") or component.version() == "(devel)"


def _is_cachi2_non_registry_dependency(component: SBOMItem) -> bool:
    """
    Check if Cachi2 component was fetched from a VCS or a direct file location.

    Cachi2 reports non-registry components in a different way from Syft, so the reports from
    Syft need to be removed.

    Unfortunately, there's no way to determine which components are non-registry by looking
    at the Syft report alone. This function is meant to create a list of non-registry components
    from Cachi2's SBOM, then remove the corresponding ones reported by Syft for the merged SBOM.

    Note that this function is only applicable for PyPI or NPM components.
    """

    def is_external(purl: PackageURL) -> bool:
        qualifiers = purl.qualifiers or {}
        return purl.type in ("pypi", "npm") and ("vcs_url" in qualifiers or "download_url" in qualifiers)

    return any(map(is_external, component.all_purls()))


def _unique_key_cachi2(component: SBOMItem) -> str:
    """
    Create a unique key from Cachi2 reported components.

    This is done by taking a purl and removing any qualifiers and subpaths.

    See https://github.com/package-url/purl-spec/tree/master#purl for more info on purls.
    """
    purl = component.purl()
    if not purl:
        raise ValueError(f"cachi2 component with no purl? name={component.name()}, version={component.version()}")
    return purl._replace(qualifiers=None, subpath=None).to_string()


def _unique_key_syft(component: SBOMItem) -> str:
    """
    Create a unique key for Syft reported components.

    This is done by taking a lowercase namespace/name, and URL encoding the version.

    Syft does not set any qualifier for NPM, Pip or Golang, so there's no need to remove them
    as done in _unique_key_cachi2.

    If a Syft component lacks a purl (e.g. type OS), we'll use its name and version instead.
    """
    purl = component.purl()
    if not purl:
        return component.name() + "@" + component.version()

    name = purl.name
    version = purl.version
    subpath = purl.subpath

    if purl.type == "pypi":
        name = name.lower()

    if purl.type == "golang":
        if version:
            version = quote_plus(version)
        if subpath and _subpath_is_version(subpath):
            # put the module version where it belongs (in the module name)
            name = f"{name}/{subpath}"
            subpath = None

    return purl._replace(name=name, version=version, subpath=subpath).to_string()


def _get_syft_component_filter(cachi_sbom_components: Sequence[SBOMItem]) -> Callable[[SBOMItem], bool]:
    """
    Get a function that filters out Syft components for the merged SBOM.

    This function currently considers a Syft component as a duplicate/removable if:
    - it has the same key as a Cachi2 component
    - it is a local Golang replacement
    - is a non-registry component also reported by Cachi2

    Note that for the last bullet, we can only rely on the Pip dependency's name to find a
    duplicate. This is because Cachi2 does not report a non-PyPI Pip dependency's version.

    Even though multiple versions of a same dependency can be available in the same project,
    we are removing all Syft instances by name only because Cachi2 will report them correctly,
    given that it scans all the source code properly and the image is built hermetically.
    """
    cachi2_non_registry_components = [
        component.name() for component in cachi_sbom_components if _is_cachi2_non_registry_dependency(component)
    ]
    cachi2_local_paths = {
        Path(subpath) for component in cachi_sbom_components if (purl := component.purl()) and (subpath := purl.subpath)
    }

    cachi2_indexed_components = {_unique_key_cachi2(component): component for component in cachi_sbom_components}

    def is_duplicate_non_registry_component(component: SBOMItem) -> bool:
        return component.name() in cachi2_non_registry_components

    def is_duplicate_npm_localpath_component(component: SBOMItem) -> bool:
        purl = component.purl()
        if not purl or purl.type != "npm":
            return False
        # instead of reporting path dependencies as pkg:npm/name@version?...#subpath,
        # syft repots them as pkg:npm/subpath@version
        return Path(purl.namespace or "", purl.name) in cachi2_local_paths

    def component_is_duplicated(component: SBOMItem) -> bool:
        key = _unique_key_syft(component)

        return (
            _is_syft_local_golang_component(component)
            or is_duplicate_non_registry_component(component)
            or is_duplicate_npm_localpath_component(component)
            or key in cachi2_indexed_components.keys()
        )

    return component_is_duplicated


def _merge_tools_metadata(syft_sbom: dict[Any, Any], cachi2_sbom: dict[Any, Any]) -> None:
    """Merge the content of tools in the metadata section of the SBOM.

    With CycloneDX 1.5, a new format for specifying tools was introduced, and the format from 1.4
    was marked as deprecated.

    This function aims to support both formats in the Syft SBOM. We're assuming the Cachi2 SBOM
    was generated with the same version as this script, and it will be in the older format.
    """
    syft_tools = syft_sbom["metadata"]["tools"]
    cachi2_tools = cachi2_sbom["metadata"]["tools"]

    if isinstance(syft_tools, dict):
        components = []

        for t in cachi2_tools:
            components.append(
                {
                    "author": t["vendor"],
                    "name": t["name"],
                    "type": "application",
                }
            )

        syft_tools["components"].extend(components)
    elif isinstance(syft_tools, list):
        syft_tools.extend(cachi2_tools)
    else:
        raise RuntimeError(
            "The .metadata.tools JSON key is in an unexpected format. "
            f"Expected dict or list, got {type(syft_tools)}."
        )


def merge_components[T: SBOMItem](cachi2_components: Sequence[T], syft_components: Sequence[T]) -> list[T]:
    is_duplicate_component = _get_syft_component_filter(cachi2_components)
    merged = [c for c in syft_components if not is_duplicate_component(c)]
    merged += cachi2_components
    return merged


def merge_cyclonedx_sboms(cachi2_sbom: dict[str, Any], syft_sbom: dict[str, Any]) -> dict[str, Any]:
    """Merge the data from the cachi2 CycloneDX SBOM into the Syft CycloneDX SBOM."""
    cachi2_components = wrap_as_cdx(cachi2_sbom["components"])
    syft_components = wrap_as_cdx(syft_sbom.get("components", []))
    merged_components = merge_components(cachi2_components, syft_components)

    merged_sbom = syft_sbom | {"components": unwrap_from_cdx(merged_components)}
    _merge_tools_metadata(merged_sbom, cachi2_sbom)
    return merged_sbom


def _merge_spdx_creation_info(
    cachi2_creation_info: dict[str, Any], syft_creation_info: dict[str, Any]
) -> dict[str, Any]:
    creation_info = syft_creation_info.copy()
    creation_info["creators"].extend(cachi2_creation_info["creators"])
    return creation_info


def _merge_spdx_relationships(
    cachi2_relationships: list[dict[str, Any]],
    syft_relationships: list[dict[str, Any]],
    replace_spdxid: Callable[[str], str | None],
) -> list[dict[str, Any]]:
    """Merge two lists of SPDX relationships.

    Modify relationships according to the replace_spdxid function. Given an SPDXID, it can return:
    - the same SPDXID (relationship is unchanged)
    - a different SPDXID (relationship is updated)
    - None (relationship is dropped)
    """
    merged_relationships = []

    for relationship in syft_relationships + cachi2_relationships:
        element = replace_spdxid(relationship["spdxElementId"])
        related_element = replace_spdxid(relationship["relatedSpdxElement"])

        if element and related_element:
            merged_relationships.append(
                relationship | {"spdxElementId": element, "relatedSpdxElement": related_element}
            )

    return merged_relationships


def merge_spdx_sboms(cachi2_sbom: dict[str, Any], syft_sbom: dict[str, Any]) -> dict[str, Any]:
    """Merge the data from the cachi2 SPDX SBOM into the Syft SPDX SBOM."""
    cachi2_packages = wrap_as_spdx(cachi2_sbom.get("packages", []))
    syft_packages = wrap_as_spdx(syft_sbom.get("packages", []))

    merged_packages = merge_components(cachi2_packages, syft_packages)
    merged_packages_by_id = {p.spdxid(): p for p in merged_packages}

    def replace_spdxid(spdxid: str) -> str | None:
        if spdxid == cachi2_sbom["SPDXID"]:
            # The merged document can only have one SPDXID, keep the Syft one
            return syft_sbom["SPDXID"]
        if spdxid == syft_sbom["SPDXID"] or spdxid in merged_packages_by_id:
            # Unchanged
            return spdxid
        # Drop
        return None

    merged_relationships = _merge_spdx_relationships(
        cachi2_sbom.get("relationships", []),
        syft_sbom.get("relationships", []),
        replace_spdxid=replace_spdxid,
    )
    merged_creation_info = _merge_spdx_creation_info(
        cachi2_sbom["creationInfo"],
        syft_sbom["creationInfo"],
    )

    merged_sbom = syft_sbom | {
        "packages": unwrap_from_spdx(merged_packages),
        "relationships": merged_relationships,
        "creationInfo": merged_creation_info,
    }
    return merged_sbom


def detect_sbom_type(sbom: dict[str, Any]) -> Literal["cyclonedx", "spdx"]:
    if sbom.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    elif sbom.get("spdxVersion"):
        return "spdx"
    else:
        raise ValueError("Unknown SBOM format")


def merge_sboms(cachi2_sbom_path: str, syft_sbom_path: str) -> str:
    """Merge Cachi2 components into the Syft SBOM while removing duplicates."""
    with open(cachi2_sbom_path) as file:
        cachi2_sbom = json.load(file)

    with open(syft_sbom_path) as file:
        syft_sbom = json.load(file)

    fmt = detect_sbom_type(cachi2_sbom)
    fmt2 = detect_sbom_type(syft_sbom)
    if fmt != fmt2:
        raise ValueError(f"Mismatched SBOM formats; cachi2 SBOM is {fmt} but Syft SBOM is {fmt2}")

    if fmt == "cyclonedx":
        merged_sbom = merge_cyclonedx_sboms(cachi2_sbom, syft_sbom)
    else:
        merged_sbom = merge_spdx_sboms(cachi2_sbom, syft_sbom)

    return json.dumps(merged_sbom, indent=2)


if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument("cachi2_sbom_path")
    parser.add_argument("syft_sbom_path")

    args = parser.parse_args()

    merged_sbom = merge_sboms(args.cachi2_sbom_path, args.syft_sbom_path)

    print(merged_sbom)
