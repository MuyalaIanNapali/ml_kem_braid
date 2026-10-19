use crate::ml_kem_braid::gf16;

pub fn multiply(
    matrix: &[Vec<u16>],
    chunks: &[Vec<u16>],
) -> Vec<Vec<u16>> {
    assert!(!matrix.is_empty(), "Matrix cannot be empty");
    assert!(!chunks.is_empty(), "Chunks cannot be empty");

    let rows = matrix.len();
    let columns = matrix[0].len();

    assert_eq!(chunks.len(), columns, "Matrix dimensions do not match");

    let elements_per_chunk = chunks[0].len();

    assert!(
        matrix.iter().all(|row| row.len() == columns),
        "Invalid matrix dimensions"
    );

    assert!(
        chunks
            .iter()
            .all(|chunk| chunk.len() == elements_per_chunk),
        "All chunks must contain the same number of elements"
    );

    let mut result = vec![vec![0u16; elements_per_chunk]; rows];

    for i in 0..rows {
        for j in 0..columns {
            let coefficient = matrix[i][j];

            if coefficient == 0 {
                continue;
            }

            for e in 0..elements_per_chunk {
                let product =
                    gf16::multiply(coefficient, chunks[j][e]);

                result[i][e] =
                    gf16::add(result[i][e], product);
            }
        }
    }

    result
}

pub fn inverse(matrix: &[Vec<u16>]) -> Vec<Vec<u16>> {
    let n = matrix.len();

    assert!(n > 0, "Matrix cannot be empty");

    assert!(
        matrix.iter().all(|row| row.len() == n),
        "Matrix must be square"
    );

    // [A | I]
    let mut augmented = vec![vec![0u16; 2 * n]; n];

    for row in 0..n {
        for column in 0..2 * n {
            augmented[row][column] = if column < n {
                matrix[row][column]
            } else if column - n == row {
                1
            } else {
                0
            };
        }
    }

    // Gauss-Jordan elimination
    for column in 0..n {
        let mut pivot = column;

        while pivot < n && augmented[pivot][column] == 0 {
            pivot += 1;
        }

        assert!(
            pivot < n,
            "Matrix is not invertible"
        );

        // Swap rows
        if pivot != column {
            augmented.swap(column, pivot);
        }

        // Normalize pivot
        let pivot_value = augmented[column][column];

        let pivot_inverse =
            gf16::inverse(pivot_value);

        for j in 0..2 * n {
            augmented[column][j] =
                gf16::multiply(
                    augmented[column][j],
                    pivot_inverse,
                );
        }

        // Eliminate column
        for row in 0..n {
            if row == column {
                continue;
            }

            let factor = augmented[row][column];

            if factor == 0 {
                continue;
            }

            for j in 0..2 * n {
                let product =
                    gf16::multiply(
                        factor,
                        augmented[column][j],
                    );

                augmented[row][j] =
                    gf16::add(
                        augmented[row][j],
                        product,
                    );
            }
        }
    }

    // Extract inverse
    let mut result = vec![vec![0u16; n]; n];

    for row in 0..n {
        for column in 0..n {
            result[row][column] =
                augmented[row][n + column];
        }
    }

    result
}

fn parity_coefficient(
    p: usize,
    i: usize,
) -> u16 {
    // Kotlin:
    //
    // val x = p + 1
    // return GF16.pow(x, i)

    let x = (p + 1) as u16;

    gf16::pow(x, i as u32)
}

pub fn create_generator_matrix(
    k: usize,
    m: usize,
) -> Vec<Vec<u16>> {
    let n = k + m;

    let mut matrix =
        vec![vec![0u16; k]; n];

    // Identity matrix.
    //
    // [ I ]
    // [ P ]
    //
    for i in 0..k {
        matrix[i][i] = 1;
    }

    // Parity matrix.
    for p in 0..m {
        for i in 0..k {
            matrix[k + p][i] =
                parity_coefficient(p, i);
        }
    }

    matrix
}