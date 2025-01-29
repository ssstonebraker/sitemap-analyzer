#!/usr/bin/env python3
"""
Sitemap Analyzer - A tool to analyze and count unique URLs from a website's sitemap.
"""

import argparse
import logging
import sys
from collections import defaultdict
from datetime import datetime
from typing import Dict, Optional, Set
from urllib.parse import urlparse

import requests
import xml.etree.ElementTree as ET


class SitemapAnalyzer:
    """Analyzes website sitemaps and generates URL statistics."""

    def __init__(self, domain: str):
        """
        Initialize the SitemapAnalyzer.

        Args:
            domain: The domain to analyze (e.g., 'example.com')
        """
        self.domain = domain
        self.unique_urls: Set[str] = set()
        self.lastmod_dates: list = []
        self.sections: Dict[str, int] = defaultdict(int)
        self.logger = self._setup_logger()

    @staticmethod
    def _setup_logger() -> logging.Logger:
        """Configure and return a logger instance."""
        logging.basicConfig(
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        return logging.getLogger(__name__)

    def get_robots_txt(self) -> Optional[str]:
        """
        Fetch and parse robots.txt to find sitemap location.

        Returns:
            Optional[str]: URL of the sitemap if found, None otherwise
        """
        try:
            response = requests.get(
                f"https://{self.domain}/robots.txt",
                timeout=10
            )
            response.raise_for_status()

            for line in response.text.splitlines():
                if line.lower().startswith('sitemap:'):
                    return line.split(': ')[1].strip()
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching robots.txt: {e}")
        return None

    def parse_sitemap(self, url: str) -> None:
        """
        Parse sitemap and any nested sitemaps recursively.

        Args:
            url: The URL of the sitemap to parse
        """
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            root = ET.fromstring(response.content)
            namespace = {'ns': root.tag.split('}')[0].strip('{')}

            # Handle sitemap index
            if 'sitemapindex' in root.tag:
                for sitemap in root.findall('.//ns:loc', namespace):
                    if sitemap.text and 'sitemaps.org' not in sitemap.text:
                        self.parse_sitemap(sitemap.text)

            # Handle regular sitemap
            else:
                for url_element in root.findall('.//ns:url', namespace):
                    loc = url_element.find('ns:loc', namespace)
                    if loc is not None and loc.text:
                        if 'sitemaps.org' not in loc.text:
                            self.unique_urls.add(loc.text)
                            self._analyze_url(loc.text)

                        lastmod = url_element.find('ns:lastmod', namespace)
                        if lastmod is not None and lastmod.text:
                            self.lastmod_dates.append(lastmod.text)

        except (requests.exceptions.RequestException, ET.ParseError) as e:
            self.logger.error(f"Error parsing sitemap {url}: {e}")

    def _analyze_url(self, url: str) -> None:
        """
        Analyze URL pattern and structure.

        Args:
            url: The URL to analyze
        """
        parsed = urlparse(url)
        path = parsed.path.strip('/')
        if path:
            section = path.split('/')[0]
            self.sections[section] += 1

    def generate_report(self) -> Dict:
        """
        Generate analysis report.

        Returns:
            Dict containing analysis results
        """
        return {
            'total_urls': len(self.unique_urls),
            'sections': dict(self.sections),
            'date_range': {
                'earliest': min(self.lastmod_dates) if self.lastmod_dates else None,
                'latest': max(self.lastmod_dates) if self.lastmod_dates else None
            },
            'hierarchy_levels': self._analyze_hierarchy_levels()
        }

    def _analyze_hierarchy_levels(self) -> Dict[int, int]:
        """
        Analyze URL hierarchy levels.

        Returns:
            Dict mapping hierarchy depth to URL count
        """
        levels = defaultdict(int)
        for url in self.unique_urls:
            path = urlparse(url).path.strip('/')
            depth = len(path.split('/')) if path else 0
            levels[depth] += 1
        return dict(levels)

    def run_analysis(self) -> Optional[Dict]:
        """
        Run the complete sitemap analysis.

        Returns:
            Optional[Dict]: Analysis report if successful, None otherwise
        """
        self.logger.info(f"Starting analysis for {self.domain}")

        sitemap_url = self.get_robots_txt()
        if not sitemap_url:
            self.logger.error("No sitemap found in robots.txt")
            return None

        self.parse_sitemap(sitemap_url)
        return self.generate_report()


def main():
    """Main entry point for the sitemap analyzer."""
    parser = argparse.ArgumentParser(
        description='Analyze and count unique URLs from a website sitemap',
        epilog='Example: %(prog)s --domain example.com'
    )

    parser.add_argument(
        '--domain',
        type=str,
        required=True,
        help='Domain to analyze (e.g., example.com)'
    )

    parser.add_argument(
        '--verbose',
        '-v',
        action='count',
        default=0,
        help='Increase output verbosity (use -v, -vv, or -vvv for more detail)'
    )

    args = parser.parse_args()

    try:
        analyzer = SitemapAnalyzer(args.domain)

        if args.verbose > 0:
            log_levels = [logging.INFO, logging.DEBUG]
            analyzer.logger.setLevel(log_levels[min(args.verbose - 1, len(log_levels) - 1)])

        report = analyzer.run_analysis()

        if report:
            print("\nSitemap Analysis Report")
            print("=====================")
            print(f"Domain: {args.domain}")
            print(f"Total Unique URLs: {report['total_urls']}")

            print("\nContent Sections:")
            for section, count in sorted(report['sections'].items()):
                print(f"- {section}: {count} URLs")

            print("\nURL Hierarchy:")
            for level, count in sorted(report['hierarchy_levels'].items()):
                print(f"- Level {level}: {count} URLs")

            if report['date_range']['earliest']:
                print("\nLast Modified Date Range:")
                print(f"- Earliest: {report['date_range']['earliest']}")
                print(f"- Latest: {report['date_range']['latest']}")

            return 0
        return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

