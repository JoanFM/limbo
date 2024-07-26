use std::rc::Rc;

use crate::Result;
use sqlite3_parser::ast::{self, JoinOperator, JoinType};

use crate::function::AggFunc;
use crate::schema::{Column, PseudoTable, Schema};
use crate::translate::expr::analyze_columns;
use crate::translate::expr::maybe_apply_affinity;
use crate::translate::expr::translate_expr;
use crate::translate::normalize_ident;
use crate::translate::where_clause::{
    process_where, translate_processed_where, translate_where, ProcessedWhereClause,
};
use crate::translate::{Insn, LimitInfo};
use crate::types::{OwnedRecord, OwnedValue};
use crate::vdbe::{builder::ProgramBuilder, Program};
use crate::{function::Func, schema::Table, vdbe::BranchOffset};

use super::SortInfo;

#[derive(Debug)]
pub struct SrcTable<'a> {
    pub table: Table,
    pub identifier: String,
    pub join_info: Option<&'a ast::JoinedSelectTable>,
}

impl SrcTable<'_> {
    pub fn is_outer_join(&self) -> bool {
        if let Some(ast::JoinedSelectTable {
            operator: JoinOperator::TypedJoin(Some(join_type)),
            ..
        }) = self.join_info
        {
            if *join_type == JoinType::LEFT | JoinType::OUTER {
                true
            } else if *join_type == JoinType::RIGHT | JoinType::OUTER {
                true
            } else {
                false
            }
        } else {
            false
        }
    }
}

#[derive(Debug)]
pub struct ColumnInfo<'a> {
    pub func: Option<Func>,
    pub args: &'a Option<Vec<ast::Expr>>,
    pub columns_to_allocate: usize, /* number of result columns this col will result on */
}

impl<'a> ColumnInfo<'a> {
    pub fn new() -> Self {
        Self {
            func: None,
            args: &None,
            columns_to_allocate: 1,
        }
    }

    pub fn is_aggregation_function(&self) -> bool {
        matches!(self.func, Some(Func::Agg(_)))
    }
}
#[derive(Debug)]
pub struct LeftJoinBookkeeping {
    // integer register that holds a flag that is set to true if the current row has a match for the left join
    pub match_flag_register: usize,
    // label for the instruction that sets the match flag to true
    pub set_match_flag_true_label: BranchOffset,
    // label for the instruction where the program jumps to if the current row has a match for the left join
    pub on_match_jump_to_label: BranchOffset,
}

#[derive(Debug)]
pub struct LoopInfo {
    // The table or table alias that we are looping over
    pub identifier: String,
    // Metadata about a left join, if any
    pub left_join_bookkeeping: Option<LeftJoinBookkeeping>,
    // The label for the instruction that reads the next row for this table
    pub next_row_label: BranchOffset,
    // The label for the instruction that rewinds the cursor for this table
    pub rewind_label: BranchOffset,
    // The label for the instruction that is jumped to in the Rewind instruction if the table is empty
    pub rewind_on_empty_label: BranchOffset,
    // The ID of the cursor that is opened for this table
    pub open_cursor: usize,
}
#[derive(Debug)]
pub struct Select<'a> {
    pub columns: &'a Vec<ast::ResultColumn>,
    pub column_info: Vec<ColumnInfo<'a>>,
    pub src_tables: Vec<SrcTable<'a>>, // Tables we use to get data from. This includes "from" and "joins"
    pub limit: &'a Option<ast::Limit>,
    pub order_by: &'a Option<Vec<ast::SortedColumn>>,
    pub exist_aggregation: bool,
    pub where_clause: &'a Option<ast::Expr>,
    /// Ordered list of opened read table loops
    /// Used for generating a loop that looks like this:
    /// cursor 0 = open table 0
    /// for each row in cursor 0
    ///     cursor 1 = open table 1
    ///     for each row in cursor 1
    ///         ...
    ///     end cursor 1
    /// end cursor 0
    pub loops: Vec<LoopInfo>,
}

pub fn build_select<'a>(schema: &Schema, select: &'a ast::Select) -> Result<Select<'a>> {
    match &select.body.select {
        ast::OneSelect::Select {
            columns,
            from: Some(from),
            where_clause,
            ..
        } => {
            let (table_name, maybe_alias) = match &from.select {
                Some(select_table) => match select_table.as_ref() {
                    ast::SelectTable::Table(name, alias, ..) => (
                        &name.name,
                        alias.as_ref().map(|als| match als {
                            ast::As::As(alias) => alias,     // users as u
                            ast::As::Elided(alias) => alias, // users u
                        }),
                    ),
                    _ => todo!(),
                },
                None => todo!(),
            };
            let table_name = &table_name.0;
            let maybe_alias = maybe_alias.map(|als| &als.0);
            let table = match schema.get_table(table_name) {
                Some(table) => table,
                None => crate::bail_parse_error!("no such table: {}", table_name),
            };
            let identifier = normalize_ident(maybe_alias.unwrap_or(table_name));
            let mut joins = Vec::new();
            joins.push(SrcTable {
                table: Table::BTree(table.clone()),
                identifier,
                join_info: None,
            });
            if let Some(selected_joins) = &from.joins {
                for join in selected_joins {
                    let (table_name, maybe_alias) = match &join.table {
                        ast::SelectTable::Table(name, alias, ..) => (
                            &name.name,
                            alias.as_ref().map(|als| match als {
                                ast::As::As(alias) => alias,     // users as u
                                ast::As::Elided(alias) => alias, // users u
                            }),
                        ),
                        _ => todo!(),
                    };
                    let table_name = &table_name.0;
                    let maybe_alias = maybe_alias.as_ref().map(|als| &als.0);
                    let table = match schema.get_table(table_name) {
                        Some(table) => table,
                        None => {
                            crate::bail_parse_error!("no such table: {}", table_name)
                        }
                    };
                    let identifier = normalize_ident(maybe_alias.unwrap_or(table_name));

                    joins.push(SrcTable {
                        table: Table::BTree(table),
                        identifier,
                        join_info: Some(join),
                    });
                }
            }

            let _table = Table::BTree(table);
            let column_info = analyze_columns(columns, &joins);
            let exist_aggregation = column_info
                .iter()
                .any(|info| info.is_aggregation_function());

            if let Some(mut order_by) = select.order_by.clone() {
                for column in order_by.iter_mut() {
                    match &mut column.expr {
                        ast::Expr::Literal(lit) => match lit {
                            ast::Literal::Numeric(num) => {
                                let num_i = match num.parse::<usize>() {
                                    Ok(i) => i,
                                    Err(_) => todo!(),
                                };

                                if let Some(new_column) = columns.get(num_i) {
                                    match new_column {
                                        ast::ResultColumn::Expr(expr, _) => {
                                            column.expr = expr.clone()
                                        }
                                        ast::ResultColumn::Star => todo!(),
                                        ast::ResultColumn::TableStar(_) => todo!(),
                                    }
                                }
                            }
                            _ => continue,
                        },
                        _ => continue,
                    }
                }
                return Ok(Select {
                    columns,
                    column_info,
                    src_tables: joins,
                    limit: &select.limit,
                    order_by: Some(order_by),
                    exist_aggregation,
                    where_clause,
                    loops: Vec::new(),
                });
            }
            Ok(Select {
                columns,
                column_info,
                src_tables: joins,
                limit: &select.limit,
                order_by: &select.order_by,
                exist_aggregation,
                where_clause,
                loops: Vec::new(),
            })
        }
        ast::OneSelect::Select {
            columns,
            from: None,
            where_clause,
            ..
        } => {
            let column_info = analyze_columns(columns, &Vec::new());
            let exist_aggregation = column_info
                .iter()
                .any(|info| info.is_aggregation_function());
            Ok(Select {
                columns,
                column_info,
                src_tables: Vec::new(),
                limit: &select.limit,
                order_by: &select.order_by,
                where_clause,
                exist_aggregation,
                loops: Vec::new(),
            })
        }
        _ => todo!(),
    }
}

/// Generate code for a SELECT statement.
pub fn translate_select(mut select: Select) -> Result<Program> {
    let mut program = ProgramBuilder::new();
    let init_label = program.allocate_label();
    program.emit_insn_with_label_dependency(
        Insn::Init {
            target_pc: init_label,
        },
        init_label,
    );
    let start_offset = program.offset();

    let mut sort_info = if let Some(order_by) = select.order_by {
        let sorter_cursor = program.alloc_cursor_id(None, None);
        let mut order = Vec::new();
        for col in order_by {
            order.push(OwnedValue::Integer(if let Some(ord) = col.order {
                ord as i64
            } else {
                0
            }));
        }
        program.emit_insn(Insn::SorterOpen {
            cursor_id: sorter_cursor,
            order: OwnedRecord::new(order),
            columns: select.column_info.len() + 1, // +1 for the key
        });
        Some(SortInfo {
            sorter_cursor,
            sorter_reg: 0, // will be overwritten later
            count: 0,      // will be overwritten later
        })
    } else {
        None
    };

    let limit_info = if let Some(limit) = &select.limit {
        assert!(limit.offset.is_none());
        let target_register = program.alloc_register();
        let limit_reg = translate_expr(&mut program, &select, &limit.expr, target_register, None)?;
        let num = if let ast::Expr::Literal(ast::Literal::Numeric(num)) = &limit.expr {
            num.parse::<i64>()?
        } else {
            todo!();
        };
        let goto_label = program.allocate_label();
        if num == 0 {
            program.emit_insn_with_label_dependency(
                Insn::Goto {
                    target_pc: goto_label,
                },
                goto_label,
            );
        }
        Some(LimitInfo {
            limit_reg,
            num,
            goto_label,
        })
    } else {
        None
    };

    if !select.src_tables.is_empty() {
        translate_tables_begin(&mut program, &mut select)?;

        let (register_start, column_count) = if let Some(sort_columns) = select.order_by {
            let start = program.next_free_register();
            for col in sort_columns.iter() {
                let target = program.alloc_register();
                translate_expr(&mut program, &select, &col.expr, target, None)?;
            }
            let (_, result_cols_count) = translate_columns(&mut program, &select, None)?;
            sort_info
                .as_mut()
                .map(|inner| inner.count = result_cols_count + sort_columns.len() + 1); // +1 for the key
            (start, result_cols_count + sort_columns.len())
        } else {
            translate_columns(&mut program, &select, None)?
        };

        if !select.exist_aggregation {
            if let Some(ref mut sort_info) = sort_info {
                let dest = program.alloc_register();
                program.emit_insn(Insn::MakeRecord {
                    start_reg: register_start,
                    count: column_count,
                    dest_reg: dest,
                });
                program.emit_insn(Insn::SorterInsert {
                    cursor_id: sort_info.sorter_cursor,
                    record_reg: dest,
                });
                sort_info.sorter_reg = register_start;
            } else {
                program.emit_insn(Insn::ResultRow {
                    start_reg: register_start,
                    count: column_count,
                });
                emit_limit_insn(&limit_info, &mut program);
            }
        }

        translate_tables_end(&mut program, &select);

        if select.exist_aggregation {
            let mut target = register_start;
            for info in &select.column_info {
                if let Some(Func::Agg(func)) = &info.func {
                    program.emit_insn(Insn::AggFinal {
                        register: target,
                        func: func.clone(),
                    });
                }
                target += info.columns_to_allocate;
            }
            // only one result row
            program.emit_insn(Insn::ResultRow {
                start_reg: register_start,
                count: column_count,
            });
            emit_limit_insn(&limit_info, &mut program);
        }
    } else {
        assert!(!select.exist_aggregation);
        assert!(sort_info.is_none());
        let where_maybe = translate_where(&select, &mut program)?;
        let (register_start, count) = translate_columns(&mut program, &select, None)?;
        if let Some(where_clause_label) = where_maybe {
            program.resolve_label(where_clause_label, program.offset() + 1);
        }
        program.emit_insn(Insn::ResultRow {
            start_reg: register_start,
            count,
        });
        emit_limit_insn(&limit_info, &mut program);
    };

    // now do the sort for ORDER BY
    if select.order_by.is_some() {
        let _ = translate_sorter(&select, &mut program, &sort_info.unwrap(), &limit_info);
    }

    program.emit_insn(Insn::Halt);
    let halt_offset = program.offset() - 1;
    if let Some(limit_info) = limit_info {
        if limit_info.goto_label < 0 {
            program.resolve_label(limit_info.goto_label, halt_offset);
        }
    }
    program.resolve_label(init_label, program.offset());
    program.emit_insn(Insn::Transaction);
    program.emit_constant_insns();
    program.emit_insn(Insn::Goto {
        target_pc: start_offset,
    });
    program.resolve_deferred_labels();
    Ok(program.build())
}

fn emit_limit_insn(limit_info: &Option<LimitInfo>, program: &mut ProgramBuilder) {
    if limit_info.is_none() {
        return;
    }
    let limit_info = limit_info.as_ref().unwrap();
    if limit_info.num > 0 {
        program.emit_insn_with_label_dependency(
            Insn::DecrJumpZero {
                reg: limit_info.limit_reg,
                target_pc: limit_info.goto_label,
            },
            limit_info.goto_label,
        );
    }
}

fn translate_sorter(
    select: &Select,
    program: &mut ProgramBuilder,
    sort_info: &SortInfo,
    limit_info: &Option<LimitInfo>,
) -> Result<()> {
    assert!(sort_info.count > 0);
    let mut pseudo_columns = Vec::new();
    for col in select.columns.iter() {
        match col {
            ast::ResultColumn::Expr(expr, _) => match expr {
                ast::Expr::Id(ident) => {
                    pseudo_columns.push(Column {
                        name: normalize_ident(&ident.0),
                        primary_key: false,
                        ty: crate::schema::Type::Null,
                    });
                }
                ast::Expr::Qualified(table_name, ident) => {
                    pseudo_columns.push(Column {
                        name: normalize_ident(format!("{}.{}", table_name.0, ident.0).as_str()),
                        primary_key: false,
                        ty: crate::schema::Type::Null,
                    });
                }
                other => {
                    todo!("translate_sorter: {:?}", other);
                }
            },
            ast::ResultColumn::Star => {}
            ast::ResultColumn::TableStar(_) => {}
        }
    }
    let pseudo_cursor = program.alloc_cursor_id(
        None,
        Some(Table::Pseudo(Rc::new(PseudoTable {
            columns: pseudo_columns,
        }))),
    );
    let pseudo_content_reg = program.alloc_register();
    program.emit_insn(Insn::OpenPseudo {
        cursor_id: pseudo_cursor,
        content_reg: pseudo_content_reg,
        num_fields: sort_info.count,
    });
    let label = program.allocate_label();
    program.emit_insn_with_label_dependency(
        Insn::SorterSort {
            cursor_id: sort_info.sorter_cursor,
            pc_if_empty: label,
        },
        label,
    );
    let sorter_data_offset = program.offset();
    program.emit_insn(Insn::SorterData {
        cursor_id: sort_info.sorter_cursor,
        dest_reg: pseudo_content_reg,
        pseudo_cursor,
    });
    let (register_start, count) = translate_columns(program, select, Some(pseudo_cursor))?;
    program.emit_insn(Insn::ResultRow {
        start_reg: register_start,
        count,
    });
    emit_limit_insn(limit_info, program);
    program.emit_insn(Insn::SorterNext {
        cursor_id: sort_info.sorter_cursor,
        pc_if_next: sorter_data_offset,
    });
    program.resolve_label(label, program.offset());
    Ok(())
}

fn translate_tables_begin(program: &mut ProgramBuilder, select: &mut Select) -> Result<()> {
    for join in &select.src_tables {
        let loop_info = translate_table_open_cursor(program, join);
        select.loops.push(loop_info);
    }

    let processed_where = process_where(program, select)?;

    for loop_info in &select.loops {
        translate_table_open_loop(program, select, loop_info, &processed_where)?;
    }

    Ok(())
}

fn translate_tables_end(program: &mut ProgramBuilder, select: &Select) {
    // iterate in reverse order as we open cursors in order
    for table_loop in select.loops.iter().rev() {
        let cursor_id = table_loop.open_cursor;
        program.resolve_label(table_loop.next_row_label, program.offset());
        program.emit_insn(Insn::NextAsync { cursor_id });
        program.emit_insn_with_label_dependency(
            Insn::NextAwait {
                cursor_id,
                pc_if_next: table_loop.rewind_label,
            },
            table_loop.rewind_label,
        );

        if let Some(ljbk) = &table_loop.left_join_bookkeeping {
            left_join_match_flag_check(program, ljbk, cursor_id);
        }
    }
}

fn translate_table_open_cursor(program: &mut ProgramBuilder, table: &SrcTable) -> LoopInfo {
    let cursor_id =
        program.alloc_cursor_id(Some(table.identifier.clone()), Some(table.table.clone()));
    let root_page = match &table.table {
        Table::BTree(btree) => btree.root_page,
        Table::Pseudo(_) => todo!(),
    };
    program.emit_insn(Insn::OpenReadAsync {
        cursor_id,
        root_page,
    });
    program.emit_insn(Insn::OpenReadAwait);
    LoopInfo {
        identifier: table.identifier.clone(),
        left_join_bookkeeping: if table.is_outer_join() {
            Some(LeftJoinBookkeeping {
                match_flag_register: program.alloc_register(),
                on_match_jump_to_label: program.allocate_label(),
                set_match_flag_true_label: program.allocate_label(),
            })
        } else {
            None
        },
        open_cursor: cursor_id,
        next_row_label: program.allocate_label(),
        rewind_label: program.allocate_label(),
        rewind_on_empty_label: program.allocate_label(),
    }
}

/**
* initialize left join match flag to false
* if condition checks pass, it will eventually be set to true
*/
fn left_join_match_flag_initialize(program: &mut ProgramBuilder, ljbk: &LeftJoinBookkeeping) {
    program.emit_insn(Insn::Integer {
        value: 0,
        dest: ljbk.match_flag_register,
    });
}

/**
* after the relevant conditional jumps have been emitted, set the left join match flag to true
*/
fn left_join_match_flag_set_true(program: &mut ProgramBuilder, ljbk: &LeftJoinBookkeeping) {
    program.defer_label_resolution(ljbk.set_match_flag_true_label, program.offset() as usize);
    program.emit_insn(Insn::Integer {
        value: 1,
        dest: ljbk.match_flag_register,
    });
}

/**
* check if the left join match flag is set to true
* if it is, jump to the next row on the outer table
* if not, set the right table cursor's "pseudo null bit" on
* then jump to setting the left join match flag to true again,
* which will effectively emit all nulls for the right table.
*/
fn left_join_match_flag_check(
    program: &mut ProgramBuilder,
    ljbk: &LeftJoinBookkeeping,
    cursor_id: usize,
) {
    // If the left join match flag has been set to 1, we jump to the next row on the outer table (result row has been emitted already)
    program.emit_insn_with_label_dependency(
        Insn::IfPos {
            reg: ljbk.match_flag_register,
            target_pc: ljbk.on_match_jump_to_label,
            decrement_by: 0,
        },
        ljbk.on_match_jump_to_label,
    );
    // If not, we set the right table cursor's "pseudo null bit" on, which means any Insn::Column will return NULL
    program.emit_insn(Insn::NullRow { cursor_id });
    // Jump to setting the left join match flag to 1 again, but this time the right table cursor will set everything to null
    program.emit_insn_with_label_dependency(
        Insn::Goto {
            target_pc: ljbk.set_match_flag_true_label,
        },
        ljbk.set_match_flag_true_label,
    );
    // This points to the NextAsync instruction of the next table in the loop
    // (i.e. the outer table, since we're iterating in reverse order)
    program.resolve_label(ljbk.on_match_jump_to_label, program.offset());
}

fn translate_table_open_loop(
    program: &mut ProgramBuilder,
    select: &Select,
    loop_info: &LoopInfo,
    w: &ProcessedWhereClause,
) -> Result<()> {
    if let Some(ljbk) = loop_info.left_join_bookkeeping.as_ref() {
        left_join_match_flag_initialize(program, ljbk);
    }

    program.emit_insn(Insn::RewindAsync {
        cursor_id: loop_info.open_cursor,
    });
    program.defer_label_resolution(loop_info.rewind_label, program.offset() as usize);
    program.emit_insn_with_label_dependency(
        Insn::RewindAwait {
            cursor_id: loop_info.open_cursor,
            pc_if_empty: loop_info.rewind_on_empty_label,
        },
        loop_info.rewind_on_empty_label,
    );

    translate_processed_where(program, select, loop_info, w, None)?;

    if let Some(ljbk) = loop_info.left_join_bookkeeping.as_ref() {
        left_join_match_flag_set_true(program, ljbk);
    }

    Ok(())
}

fn translate_columns(
    program: &mut ProgramBuilder,
    select: &Select,
    cursor_hint: Option<usize>,
) -> Result<(usize, usize)> {
    let register_start = program.next_free_register();

    // allocate one register as output for each col
    let registers: usize = select
        .column_info
        .iter()
        .map(|col| col.columns_to_allocate)
        .sum();
    program.alloc_registers(registers);
    let count = program.next_free_register() - register_start;

    let mut target = register_start;
    for (col, info) in select.columns.iter().zip(select.column_info.iter()) {
        translate_column(program, select, col, info, target, cursor_hint)?;
        target += info.columns_to_allocate;
    }
    Ok((register_start, count))
}

fn translate_column(
    program: &mut ProgramBuilder,
    select: &Select,
    col: &ast::ResultColumn,
    info: &ColumnInfo,
    target_register: usize, // where to store the result, in case of star it will be the start of registers added
    cursor_hint: Option<usize>,
) -> Result<()> {
    match col {
        ast::ResultColumn::Expr(expr, _) => {
            if info.is_aggregation_function() {
                let _ = translate_aggregation(
                    program,
                    select,
                    expr,
                    info,
                    target_register,
                    cursor_hint,
                )?;
            } else {
                let _ = translate_expr(program, select, expr, target_register, cursor_hint)?;
            }
        }
        ast::ResultColumn::Star => {
            let mut target_register = target_register;
            for join in &select.src_tables {
                translate_table_star(join, program, target_register, cursor_hint);
                target_register += &join.table.columns().len();
            }
        }
        ast::ResultColumn::TableStar(_) => todo!(),
    }
    Ok(())
}

fn translate_table_star(
    table: &SrcTable,
    program: &mut ProgramBuilder,
    target_register: usize,
    cursor_hint: Option<usize>,
) {
    let table_cursor = program.resolve_cursor_id(&table.identifier, cursor_hint);
    let table = &table.table;
    for (i, col) in table.columns().iter().enumerate() {
        let col_target_register = target_register + i;
        if table.column_is_rowid_alias(col) {
            program.emit_insn(Insn::RowId {
                cursor_id: table_cursor,
                dest: col_target_register,
            });
        } else {
            program.emit_insn(Insn::Column {
                column: i,
                dest: col_target_register,
                cursor_id: table_cursor,
            });
            maybe_apply_affinity(col.ty, col_target_register, program);
        }
    }
}

fn translate_aggregation(
    program: &mut ProgramBuilder,
    select: &Select,
    expr: &ast::Expr,
    info: &ColumnInfo,
    target_register: usize,
    cursor_hint: Option<usize>,
) -> Result<usize> {
    let _ = expr;
    assert!(info.func.is_some());
    let func = info.func.as_ref().unwrap();
    let empty_args = &Vec::<ast::Expr>::new();
    let args = info.args.as_ref().unwrap_or(empty_args);
    let dest = match func {
        Func::Scalar(_) => {
            crate::bail_parse_error!("single row function in aggregation")
        }
        Func::Agg(agg_func) => match agg_func {
            AggFunc::Avg => {
                if args.len() != 1 {
                    crate::bail_parse_error!("avg bad number of arguments");
                }
                let expr = &args[0];
                let expr_reg = program.alloc_register();
                let _ = translate_expr(program, select, expr, expr_reg, cursor_hint)?;
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Avg,
                });
                target_register
            }
            AggFunc::Count => {
                let expr_reg = if args.is_empty() {
                    program.alloc_register()
                } else {
                    let expr = &args[0];
                    let expr_reg = program.alloc_register();
                    let _ = translate_expr(program, select, expr, expr_reg, cursor_hint);
                    expr_reg
                };
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Count,
                });
                target_register
            }
            AggFunc::GroupConcat => {
                if args.len() != 1 && args.len() != 2 {
                    crate::bail_parse_error!("group_concat bad number of arguments");
                }

                let expr_reg = program.alloc_register();
                let delimiter_reg = program.alloc_register();

                let expr = &args[0];
                let delimiter_expr: ast::Expr;

                if args.len() == 2 {
                    match &args[1] {
                        ast::Expr::Id(ident) => {
                            if ident.0.starts_with('"') {
                                delimiter_expr =
                                    ast::Expr::Literal(ast::Literal::String(ident.0.to_string()));
                            } else {
                                delimiter_expr = args[1].clone();
                            }
                        }
                        ast::Expr::Literal(ast::Literal::String(s)) => {
                            delimiter_expr =
                                ast::Expr::Literal(ast::Literal::String(s.to_string()));
                        }
                        _ => crate::bail_parse_error!("Incorrect delimiter parameter"),
                    };
                } else {
                    delimiter_expr =
                        ast::Expr::Literal(ast::Literal::String(String::from("\",\"")));
                }

                translate_expr(program, select, expr, expr_reg, cursor_hint)?;
                translate_expr(program, select, &delimiter_expr, delimiter_reg, cursor_hint)?;

                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: delimiter_reg,
                    func: AggFunc::GroupConcat,
                });

                target_register
            }
            AggFunc::Max => {
                if args.len() != 1 {
                    crate::bail_parse_error!("max bad number of arguments");
                }
                let expr = &args[0];
                let expr_reg = program.alloc_register();
                let _ = translate_expr(program, select, expr, expr_reg, cursor_hint);
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Max,
                });
                target_register
            }
            AggFunc::Min => {
                if args.len() != 1 {
                    crate::bail_parse_error!("min bad number of arguments");
                }
                let expr = &args[0];
                let expr_reg = program.alloc_register();
                let _ = translate_expr(program, select, expr, expr_reg, cursor_hint);
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Min,
                });
                target_register
            }
            AggFunc::StringAgg => {
                if args.len() != 2 {
                    crate::bail_parse_error!("string_agg bad number of arguments");
                }

                let expr_reg = program.alloc_register();
                let delimiter_reg = program.alloc_register();

                let expr = &args[0];
                let delimiter_expr: ast::Expr;

                match &args[1] {
                    ast::Expr::Id(ident) => {
                        if ident.0.starts_with('"') {
                            crate::bail_parse_error!("no such column: \",\" - should this be a string literal in single-quotes?");
                        } else {
                            delimiter_expr = args[1].clone();
                        }
                    }
                    ast::Expr::Literal(ast::Literal::String(s)) => {
                        delimiter_expr = ast::Expr::Literal(ast::Literal::String(s.to_string()));
                    }
                    _ => crate::bail_parse_error!("Incorrect delimiter parameter"),
                };

                translate_expr(program, select, expr, expr_reg, cursor_hint)?;
                translate_expr(program, select, &delimiter_expr, delimiter_reg, cursor_hint)?;

                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: delimiter_reg,
                    func: AggFunc::StringAgg,
                });

                target_register
            }
            AggFunc::Sum => {
                if args.len() != 1 {
                    crate::bail_parse_error!("sum bad number of arguments");
                }
                let expr = &args[0];
                let expr_reg = program.alloc_register();
                let _ = translate_expr(program, select, expr, expr_reg, cursor_hint)?;
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Sum,
                });
                target_register
            }
            AggFunc::Total => {
                if args.len() != 1 {
                    crate::bail_parse_error!("total bad number of arguments");
                }
                let expr = &args[0];
                let expr_reg = program.alloc_register();
                let _ = translate_expr(program, select, expr, expr_reg, cursor_hint)?;
                program.emit_insn(Insn::AggStep {
                    acc_reg: target_register,
                    col: expr_reg,
                    delimiter: 0,
                    func: AggFunc::Total,
                });
                target_register
            }
        },
    };
    Ok(dest)
}
