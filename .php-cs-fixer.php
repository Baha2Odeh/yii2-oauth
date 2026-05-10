<?php

/**
 * PHP CS Fixer configuration for yii2-oauth.
 *
 * Enforces Yii2 coding style:
 * - PSR-2 base ruleset
 * - Alphabetically ordered imports, no unused imports
 * - Short array syntax
 * - Aligned fat-arrows (=>) in multi-line arrays
 * - Single-quoted strings where possible
 * - Trailing commas in multi-line structures
 * - One space around concatenation and casts
 *
 * Run:
 *   composer cs-fix    # auto-fix all files
 *   composer cs-check  # dry-run (exit 1 if any file would change)
 */

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__ . '/src',
        __DIR__ . '/tests',
        __DIR__ . '/migrations',
    ])
    ->name('*.php')
    ->notPath('bootstrap.php');

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setRules([
        // ---- Base ruleset ----
        '@PSR2'                         => true,

        // ---- Imports ----
        'ordered_imports'               => ['sort_algorithm' => 'alpha', 'imports_order' => ['class', 'function', 'const']],
        'no_unused_imports'             => true,
        'global_namespace_import'       => ['import_classes' => false, 'import_constants' => false, 'import_functions' => false],
        'fully_qualified_strict_types'  => true,

        // ---- Arrays ----
        'array_syntax'                  => ['syntax' => 'short'],
        'trailing_comma_in_multiline'   => ['elements' => ['arrays', 'match', 'parameters']],
        'no_whitespace_before_comma_in_array' => true,
        'whitespace_after_comma_in_array'     => true,
        'trim_array_spaces'             => true,
        'array_indentation'             => true,
        'binary_operator_spaces'        => [
            'default'   => 'single_space',
            'operators' => ['=>' => 'align_single_space_minimal'],
        ],

        // ---- Strings ----
        'single_quote'                  => true,

        // ---- Operators & spacing ----
        'concat_space'                  => ['spacing' => 'one'],
        'cast_spaces'                   => ['space' => 'single'],
        'unary_operator_spaces'         => true,
        'not_operator_with_space'       => false,

        // ---- Blank lines & whitespace ----
        'no_extra_blank_lines'          => ['tokens' => ['extra', 'throw', 'use']],
        'no_trailing_whitespace'        => true,
        'no_whitespace_in_blank_line'   => true,
        'single_blank_line_at_eof'      => true,
        'blank_line_before_statement'   => ['statements' => ['return', 'throw', 'try']],

        // ---- PHP tags & declarations ----
        'no_closing_tag'                => true,
        'linebreak_after_opening_tag'   => true,

        // ---- Comments ----
        'align_multiline_comment'       => ['comment_type' => 'phpdocs_only'],
        'no_empty_comment'              => true,

        // ---- Misc ----
        'method_argument_space'         => ['on_multiline' => 'ensure_fully_multiline', 'after_heredoc' => true],
        'function_typehint_space'       => true,
        'return_type_declaration'       => ['space_before' => 'none'],
        'no_superfluous_phpdoc_tags'    => false,
        'phpdoc_align'                  => ['align' => 'left'],
    ])
    ->setFinder($finder);
