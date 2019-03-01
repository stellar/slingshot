#!/usr/bin/env ruby
require 'open-uri'
require 'pathname'
require 'pp'
DO_NOT_CHECK_HTTP_LINKS = !!ENV["DO_NOT_CHECK_HTTP_LINKS"]

# 1. Get all links
# 2. For each link, check if it's good:
#   a. If it's local anchor, check if it's in the list of anchors.
#   b. If it's local file, fetch that file and check if it's in that file's anchors.
#   c. If it's global URL, fetch URL to see if it's not 404 and well-formed.

$check_links_failed = false

def main
  dataset = {}
  markdown_filepaths = Dir["**/*.md"]

  markdown_filepaths.delete_if{|f| f =~ %r{/vendor/} }

  markdown_filepaths.each do |file|
    #$stderr.puts "Collecting links and anchors from #{file}..."
    collect_links_and_anchors(file, dataset)
  end
  markdown_filepaths.each do |file|
    puts "Checking links in #{file}"
    check_links(file, dataset[file][:links], dataset)
  end
end

def canonicalize_path_in_file(relpath, srcfilepath)
  abspath = File.expand_path(relpath, File.dirname(srcfilepath))
  # make relative to the current directory
  Pathname.new(abspath).relative_path_from(Pathname.new(Dir.pwd)).to_s
end

def collect_links_and_anchors(fp, dataset={})
  f = File.read(fp) || ""
  dataset[fp] ||= {links:nil, anchors:nil}
  ds = dataset[fp]
  ds[:links] ||= begin
    links = []
    f.dup.split("\n").each_with_index do |line, line_index|
      line.scan(%r{\[([^\]]*)\]\(([^\)]*)\)}m).each do |(title, ref)|
        lineno = line_index + 1
        links << [title, ref, lineno]
      end
    end
    links
  end
  ds[:anchors] ||= begin
    extract_anchors(f)
  end
end

def check_links(file, links, dataset = {})
  dataset["__checked_remote_urls"] ||= {}
  cache = dataset["__checked_remote_urls"]
  links.each do |(name, ref, lineno)|
    if ref[0,1] == "#"
      if !dataset[file][:anchors].include?(ref)
        $stderr.puts   "#{file}:#{lineno}: invalid anchor: [#{name}](#{ref})"
        $check_links_failed = true
      end
    elsif ref =~ %r{^https?://}
      if !check_url(ref, cache)
        $stderr.puts "#{file}:#{lineno}: external file does not load: [#{name}](#{ref})"
        $check_links_failed = true
      end
    else # cross-file link
      ref = ref.sub(%r{^\./},"")
      fn, anchor = ref.split("#")
      anchor = "##{anchor}" if anchor

      linked_fn = canonicalize_path_in_file(fn, file)

      if f = dataset[linked_fn]
        if !anchor
          # do nothing - we don't link to anything
        elsif !f[:anchors].include?(anchor)
          $stderr.puts "#{file}:#{lineno}: invalid anchor: [#{name}](#{ref}) (check headings in #{linked_fn})"
          $check_links_failed = true
        end
      else
        if !anchor && check_url(linked_fn, cache)
          # the reference is fine: the non-markdown file exists somewhere and we link to it as a whole
        else
          $stderr.puts "#{file}:#{lineno}: referenced file does not exists: [#{name}](#{ref}) (expanded to #{linked_fn})"
          $check_links_failed = true
        end
      end
    end
  end
end

def check_url(url, cache = {})
  return true if cache[url]
  if url == "https://dx.doi.org/10.6028/NIST.FIPS.202"
    true
  elsif DO_NOT_CHECK_HTTP_LINKS && url =~ /^https?:/
    true
  elsif Dir.exists?(url)
    cache[url] = "ok"
    true
  else
    # check that file exists
    x = open(url).read rescue nil
    exists = !!x
    cache[url] = exists ? "ok" : "failed"
    exists
  end
end

def extract_anchors(data)
  results = [] # list of anchors
  data.split("\n").each do |line|
    if h = extract_heading(line)
      depth, title, anchor = h
      results << anchor
    end
  end
  results
end

# Returns `nil` or `[depth, title, anchor]`
def extract_heading(line)
  if line =~ /^(#+)\s(.*)/
    prefix = $1
    title = $2
    depth = prefix.size
    anchor = "#" + title.
          downcase.
          gsub(/\W+/,"-").gsub(/(\d)\-(\d)/,"\\1\\2").
          gsub(/^\-+/,"").
          gsub(/\-+$/,"")

    [depth, title, anchor]
  end  
end

main

if $check_links_failed
  exit(1)
else
  puts "All links seem to be good."
end
